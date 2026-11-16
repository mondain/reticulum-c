/* The pieces of Nordic's legacy serial DFU (the Adafruit nRF52 bootloaders, as on the T-Echo, RAK4631 and
 * Heltec T114) that the flasher and its test share: the HCI-over-SLIP packet, its CRC16, the acknowledgement
 * check, and a reader for the stored (uncompressed) zip that adafruit-nrfutil builds.
 *
 * Packet format and timings follow Adafruit_nRF52_nrfutil's dfu_transport_serial.py (the same source
 * web/src/nrf-dfu.js follows): a 4 byte header (sequence and acknowledgement numbers with the CRC and
 * reliable bits, the payload type and length, a header checksum), the payload, and a CRC16 of both, all
 * SLIP framed. This is not Nordic's Secure DFU. */
#ifndef RETICULUM_C_NRF_DFU_H
#define RETICULUM_C_NRF_DFU_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define DFU_MAX_PAYLOAD 4095u
#define DFU_CHUNK 512u
/* the words that start every payload */
enum { DFU_INIT_PACKET = 1, DFU_START_PACKET = 3, DFU_DATA_PACKET = 4, DFU_STOP_DATA_PACKET = 5 };
#define DFU_MODE_APPLICATION 4u

static uint16_t dfu_crc16(const uint8_t *data, size_t size, uint16_t crc) {
  size_t i;
  for (i = 0; i < size; ++i) {
    crc = (uint16_t)(((crc >> 8) | (crc << 8)) & 0xffff);
    crc ^= data[i];
    crc ^= (uint16_t)((crc & 255) >> 4);
    crc ^= (uint16_t)((crc << 12) & 0xffff);
    crc ^= (uint16_t)(((crc & 255) << 5) & 0xffff);
  }
  return crc;
}
/* Builds one framed packet for `payload` with sequence number `seq`; returns its length (at most
 * 2 * (size + 6) + 2 bytes are written to out), or 0 when the payload is too long. */
static size_t dfu_frame(const uint8_t *payload, size_t size, unsigned seq, uint8_t *out) {
  uint8_t head[4];
  uint16_t crc;
  size_t o = 0, i;
  const uint8_t *parts[2];
  size_t sizes[2];
  unsigned p;
  if (size > DFU_MAX_PAYLOAD)
    return 0;
  head[0] = (uint8_t)((seq & 7) | (((seq + 1) & 7) << 3) | 0xc0);
  head[1] = (uint8_t)(14 | ((size & 15) << 4));
  head[2] = (uint8_t)(size >> 4);
  head[3] = (uint8_t)(-(head[0] + head[1] + head[2]));
  crc = dfu_crc16(head, 4, 0xffff);
  crc = dfu_crc16(payload, size, crc);
  out[o++] = 0xc0;
  parts[0] = head;
  sizes[0] = 4;
  parts[1] = payload;
  sizes[1] = size;
  for (p = 0; p < 2; ++p)
    for (i = 0; i < sizes[p]; ++i) {
      uint8_t b = parts[p][i];
      if (b == 0xc0) {
        out[o++] = 0xdb;
        out[o++] = 0xdc;
      } else if (b == 0xdb) {
        out[o++] = 0xdb;
        out[o++] = 0xdd;
      } else
        out[o++] = b;
    }
  for (i = 0; i < 2; ++i) {
    uint8_t b = i ? (uint8_t)(crc >> 8) : (uint8_t)crc;
    if (b == 0xc0) {
      out[o++] = 0xdb;
      out[o++] = 0xdc;
    } else if (b == 0xdb) {
      out[o++] = 0xdb;
      out[o++] = 0xdd;
    } else
      out[o++] = b;
  }
  out[o++] = 0xc0;
  return o;
}
/* Checks a de-framed packet as a pure acknowledgement (type 0, no payload); on success stores the
 * acknowledged sequence number in *ack. A data packet or a damaged one is not an acknowledgement. */
static int dfu_parse_ack(const uint8_t *p, size_t n, unsigned *ack) {
  size_t length;
  int has_crc;
  if (n < 4 || (uint8_t)(p[0] + p[1] + p[2] + p[3]) != 0)
    return 0;
  length = (size_t)(p[1] >> 4) | ((size_t)p[2] << 4);
  has_crc = (p[0] & 0x40) != 0;
  if (n != 4 + length + (has_crc ? 2u : 0u) || (p[1] & 15) != 0 || length != 0)
    return 0;
  if (has_crc && dfu_crc16(p, n - 2, 0xffff) != (uint16_t)(p[n - 2] | (p[n - 1] << 8)))
    return 0;
  *ack = (p[0] >> 3) & 7u;
  return 1;
}

/* ---- the DFU package (zip) ------------------------------------------------ */
static uint32_t dfu_crc32(const uint8_t *data, size_t size) {
  uint32_t crc = 0xffffffffu;
  size_t i;
  int k;
  for (i = 0; i < size; ++i) {
    crc ^= data[i];
    for (k = 0; k < 8; ++k)
      crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
  }
  return ~crc;
}
static uint32_t dfu_le32(const uint8_t *p) {
  return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static unsigned dfu_le16(const uint8_t *p) { return (unsigned)p[0] | (unsigned)p[1] << 8; }
typedef struct dfu_entry {
  char name[64];
  const uint8_t *data;
  size_t size;
} dfu_entry;
/* Finds the stored entries of a zip held in memory (at most `cap`). Returns how many, or -1 when the archive
 * is damaged, uses compression, or an entry fails its CRC32 or has an unsafe name. */
static int dfu_zip_entries(const uint8_t *zip, size_t size, dfu_entry *entries, size_t cap) {
  size_t eocd, i, count, offset;
  size_t found = 0;
  if (size < 22)
    return -1;
  for (eocd = size - 22;; --eocd) {
    if (dfu_le32(zip + eocd) == 0x06054b50u)
      break;
    if (eocd == 0 || size - eocd > 22u + 65535u)
      return -1;
  }
  count = dfu_le16(zip + eocd + 10);
  offset = dfu_le32(zip + eocd + 16);
  if (count == 0 || count > cap || offset >= size)
    return -1;
  for (i = 0; i < count; ++i) {
    size_t name_len, extra_len, comment_len, local, data_at, csize, usize, k;
    unsigned method;
    uint32_t crc;
    if (offset + 46 > size || dfu_le32(zip + offset) != 0x02014b50u)
      return -1;
    method = dfu_le16(zip + offset + 10);
    crc = dfu_le32(zip + offset + 16);
    csize = dfu_le32(zip + offset + 20);
    usize = dfu_le32(zip + offset + 24);
    name_len = dfu_le16(zip + offset + 28);
    extra_len = dfu_le16(zip + offset + 30);
    comment_len = dfu_le16(zip + offset + 32);
    local = dfu_le32(zip + offset + 42);
    if (offset + 46 + name_len + extra_len + comment_len > size || name_len == 0 || name_len >= sizeof(entries[0].name))
      return -1;
    if (method != 0 || csize != usize)
      return -1; /* compressed entries are not supported */
    for (k = 0; k < name_len; ++k) {
      char c = (char)zip[offset + 46 + k];
      if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-'))
        return -1;
      entries[found].name[k] = c;
    }
    entries[found].name[name_len] = 0;
    if (local + 30 > size || dfu_le32(zip + local) != 0x04034b50u)
      return -1;
    data_at = local + 30 + dfu_le16(zip + local + 26) + dfu_le16(zip + local + 28);
    if (data_at > size || usize > size - data_at || dfu_crc32(zip + data_at, usize) != crc)
      return -1;
    entries[found].data = zip + data_at;
    entries[found].size = usize;
    ++found;
    offset += 46 + name_len + extra_len + comment_len;
  }
  return (int)found;
}
/* Picks `key`'s string value ("bin_file": "firmware.bin") out of the manifest text; 0 when absent. */
static int dfu_manifest_string(const uint8_t *text, size_t size, const char *key, char *out, size_t cap) {
  size_t klen = strlen(key), i, j;
  for (i = 0; i + klen + 2 < size; ++i) {
    if (text[i] != '"' || memcmp(text + i + 1, key, klen) || text[i + 1 + klen] != '"')
      continue;
    j = i + klen + 2;
    while (j < size && (text[j] == ' ' || text[j] == ':' || text[j] == '\t' || text[j] == '\n' || text[j] == '\r'))
      ++j;
    if (j >= size || text[j] != '"')
      return 0;
    ++j;
    for (i = 0; j + i < size && text[j + i] != '"'; ++i)
      if (i + 1 >= cap)
        return 0;
    if (j + i >= size)
      return 0;
    memcpy(out, text + j, i);
    out[i] = 0;
    return 1;
  }
  return 0;
}
static int dfu_manifest_has_key(const uint8_t *text, size_t size, const char *key) {
  size_t klen = strlen(key), i;
  for (i = 0; i + klen + 2 <= size; ++i)
    if (text[i] == '"' && !memcmp(text + i + 1, key, klen) && text[i + 1 + klen] == '"')
      return 1;
  return 0;
}
/* The application firmware and its init packet from a DFU zip. Only application-only packages are accepted:
 * exactly three entries (manifest.json and the two it names), no bootloader or SoftDevice section. Returns 1
 * and points firmware and init into `zip`; on failure returns 0 and *why says what was wrong. */
static int dfu_package(const uint8_t *zip, size_t size, const uint8_t **firmware, size_t *firmware_size,
                       const uint8_t **init, size_t *init_size, const char **why) {
  dfu_entry entries[8];
  int n = dfu_zip_entries(zip, size, entries, 8);
  const dfu_entry *manifest = NULL, *bin = NULL, *dat = NULL;
  char bin_name[64], dat_name[64];
  int i;
  if (n < 0) {
    *why = "the package is damaged, compressed or has an unsafe entry (only stored entries are read)";
    return 0;
  }
  for (i = 0; i < n; ++i)
    if (!strcmp(entries[i].name, "manifest.json"))
      manifest = &entries[i];
  if (n != 3 || !manifest || manifest->size > 16384) {
    *why = "the package must hold manifest.json and exactly one application (a .bin and a .dat)";
    return 0;
  }
  if (dfu_manifest_has_key(manifest->data, manifest->size, "bootloader") ||
      dfu_manifest_has_key(manifest->data, manifest->size, "softdevice") ||
      dfu_manifest_has_key(manifest->data, manifest->size, "softdevice_bootloader")) {
    *why = "only application-only packages are supported; bootloader and SoftDevice updates are refused";
    return 0;
  }
  if (!dfu_manifest_has_key(manifest->data, manifest->size, "application") ||
      !dfu_manifest_string(manifest->data, manifest->size, "bin_file", bin_name, sizeof(bin_name)) ||
      !dfu_manifest_string(manifest->data, manifest->size, "dat_file", dat_name, sizeof(dat_name))) {
    *why = "the manifest names no application files";
    return 0;
  }
  for (i = 0; i < n; ++i) {
    if (!strcmp(entries[i].name, bin_name))
      bin = &entries[i];
    if (!strcmp(entries[i].name, dat_name))
      dat = &entries[i];
  }
  if (!bin || !dat || bin == dat) {
    *why = "the application files the manifest names are missing";
    return 0;
  }
  if (!bin->size || bin->size > 1024u * 1024u || !dat->size || dat->size > 512u) {
    *why = "the application or init packet has an invalid size";
    return 0;
  }
  *firmware = bin->data;
  *firmware_size = bin->size;
  *init = dat->data;
  *init_size = dat->size;
  return 1;
}
#endif
