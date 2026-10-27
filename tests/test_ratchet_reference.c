/* The ratchet file against the unmodified reference: a file the reference
 * wrote (Destination.enable_ratchets, rotated three times) loads here with the
 * same keys, and a file written here loads in the reference. */
#define _POSIX_C_SOURCE 200809L
#include <reticulum_c/rnc_security.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "%s:%d %s\n", __FILE__, __LINE__, #x);                   \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)
static rnc_result counter_rng(void *context, uint8_t *out, size_t n) {
  uint64_t *counter = context;
  while (n) {
    uint8_t seed[8], digest[32];
    size_t i, take = n < 32 ? n : 32;
    for (i = 0; i < 8; i++)
      seed[7 - i] = (uint8_t)(*counter >> (8 * i));
    ++*counter;
    CHECK(rnc_hash(seed, sizeof(seed), digest) == RNC_OK);
    memcpy(out, digest, take);
    out += take;
    n -= take;
  }
  return RNC_OK;
}
static void hex(const uint8_t *d, size_t n, char *out) {
  size_t i;
  for (i = 0; i < n; i++)
    sprintf(out + 2 * i, "%02x", d[i]);
}
static int unhex(const char *t, uint8_t *out, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) {
    unsigned v;
    if (sscanf(t + 2 * i, "%2x", &v) != 1)
      return 0;
    out[i] = (uint8_t)v;
  }
  return 1;
}
static int run_python(const char *python, char *out, size_t size,
                      const char *script, const char *a, const char *b,
                      const char *c) {
  int fds[2], status;
  size_t n = 0;
  pid_t p;
  CHECK(!pipe(fds));
  p = fork();
  CHECK(p >= 0);
  if (!p) {
    close(fds[0]);
    CHECK(dup2(fds[1], 1) >= 0 && dup2(fds[1], 2) >= 0);
    close(fds[1]);
    execl(python, python, "-c", script, a, b, c, (char *)NULL);
    _exit(127);
  }
  close(fds[1]);
  for (;;) {
    ssize_t got = read(fds[0], out + n, size - 1 - n);
    if (got <= 0)
      break;
    n += (size_t)got;
  }
  out[n] = 0;
  close(fds[0]);
  CHECK(waitpid(p, &status, 0) == p && WIFEXITED(status));
  return WEXITSTATUS(status);
}
static const char *make_script =
    "import sys, RNS\n"
    "d = sys.argv[1]\n"
    "RNS.Reticulum(configdir=d + '/cfg', loglevel=1)\n"
    "i = RNS.Identity()\n"
    "dest = RNS.Destination(i, RNS.Destination.IN, RNS.Destination.SINGLE, 'rt', 'ratchets')\n"
    "dest.enable_ratchets(d + '/ratchets')\n"
    "for _ in range(3):\n"
    "    dest.latest_ratchet_time = 0\n"
    "    dest.rotate_ratchets()\n"
    "print('prv', i.get_private_key().hex())\n"
    "print('pub', ','.join(RNS.Identity._ratchet_public_bytes(r).hex() for r in dest.ratchets))\n";
static const char *load_script =
    "import sys, RNS\n"
    "d, prv, path = sys.argv[1], sys.argv[2], sys.argv[3]\n"
    "RNS.Reticulum(configdir=d + '/cfg', loglevel=1)\n"
    "i = RNS.Identity(create_keys=False)\n"
    "i.load_private_key(bytes.fromhex(prv))\n"
    "dest = RNS.Destination(i, RNS.Destination.IN, RNS.Destination.SINGLE, 'rt', 'ratchets')\n"
    "dest.enable_ratchets(path)\n"
    "print('pub', ','.join(RNS.Identity._ratchet_public_bytes(r).hex() for r in dest.ratchets))\n";
int main(int argc, char **argv) {
  char dir[] = "/tmp/rnc-ratchet-ref-XXXXXX", cfg[300], out[8192], path[300];
  const char *python;
  FILE *f;
  CHECK(argc == 2);
  python = argv[1];
  CHECK(mkdtemp(dir));
  CHECK(snprintf(cfg, sizeof(cfg), "%s/cfg", dir) > 0 && !mkdir(cfg, 0700));
  CHECK(snprintf(path, sizeof(path), "%s/cfg/config", dir) > 0);
  f = fopen(path, "w");
  CHECK(f && fputs("[reticulum]\nenable_transport = False\nshare_instance = No\n[interfaces]\n", f) >= 0 && !fclose(f));

  /* the reference writes, this reads */
  {
    char prv_hex[200] = "", pubs[400] = "";
    uint8_t prv[64], file[2048];
    rnc_identity id;
    rnc_ratchet_key keys[8];
    rnc_ratchets store;
    char *line, *save = NULL, mine[80], *token, *tsave = NULL;
    size_t n, i;
    CHECK(run_python(python, out, sizeof(out), make_script, dir, "", "") == 0);
    for (line = strtok_r(out, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
      if (!strncmp(line, "prv ", 4))
        snprintf(prv_hex, sizeof(prv_hex), "%s", line + 4);
      else if (!strncmp(line, "pub ", 4))
        snprintf(pubs, sizeof(pubs), "%s", line + 4);
    }
    CHECK(strlen(prv_hex) == 128 && unhex(prv_hex, prv, 64));
    CHECK(rnc_identity_from_private(&id, prv) == RNC_OK);
    CHECK(snprintf(path, sizeof(path), "%s/ratchets", dir) > 0);
    f = fopen(path, "rb");
    CHECK(f);
    n = fread(file, 1, sizeof(file), f);
    fclose(f);
    CHECK(rnc_ratchets_init(&store, &id, keys, 8, 1800) == RNC_OK);
    CHECK(rnc_ratchets_import_reference(&store, &id, file, n, 1700000000u) == RNC_OK);
    CHECK(store.count == 3);
    for (i = 0, token = strtok_r(pubs, ",", &tsave); token && i < 3;
         i++, token = strtok_r(NULL, ",", &tsave)) {
      hex(keys[i].public_key, 32, mine);
      CHECK(!strcmp(mine, token));
    }
    CHECK(i == 3 && token == NULL);
    puts("reference ratchet file loaded");

    /* this writes, the reference reads */
    {
      uint64_t counter = 77;
      rnc_ratchet_key ours[6];
      rnc_ratchets mine_store;
      char want[300] = "", piece[80], got[600], *gsave = NULL;
      size_t w;
      CHECK(rnc_ratchets_init(&mine_store, &id, ours, 6, 10) == RNC_OK);
      for (i = 0; i < 4; i++)
        CHECK(rnc_ratchets_rotate(&mine_store, 1000 + i * 10, counter_rng, &counter) == RNC_OK);
      CHECK(rnc_ratchets_export_reference(&mine_store, &id, file, sizeof(file), &w) == RNC_OK);
      CHECK(snprintf(path, sizeof(path), "%s/ours.ratchets", dir) > 0);
      f = fopen(path, "wb");
      CHECK(f && fwrite(file, 1, w, f) == w && !fclose(f));
      for (i = 0; i < 4; i++) {
        hex(ours[i].public_key, 32, piece);
        strcat(want, i ? "," : "");
        strcat(want, piece);
      }
      CHECK(run_python(python, got, sizeof(got), load_script, dir, prv_hex, path) == 0);
      for (line = strtok_r(got, "\n", &gsave); line; line = strtok_r(NULL, "\n", &gsave))
        if (!strncmp(line, "pub ", 4)) {
          CHECK(!strcmp(line + 4, want));
          puts("this tool's ratchet file loaded in the reference");
          goto done;
        }
      fprintf(stderr, "no result from the reference:\n%s\n", got);
      CHECK(0);
    }
  }
done:
  {
    char cmd[400];
    CHECK(snprintf(cmd, sizeof(cmd), "rm -rf %s", dir) > 0 && system(cmd) == 0);
  }
  return 0;
}
