import JSZip from 'jszip';
import { SerialLink, aborted, bounded, delay } from './serial.js';

// Nordic legacy serial DFU (Adafruit nRF52 bootloaders), not Nordic Secure DFU.
// Packet format and timing follow Adafruit_nRF52_nrfutil's dfu_transport_serial.py.
// See public/nrf-dfu-license.txt for the retained upstream notices.
export function crc16(bytes, crc = 0xffff) {
  for (const byte of bytes) {
    crc = ((crc >>> 8) | (crc << 8)) & 0xffff;
    crc ^= byte;
    crc ^= (crc & 255) >>> 4;
    crc ^= (crc << 12) & 0xffff;
    crc ^= ((crc & 255) << 5) & 0xffff;
  }
  return crc & 0xffff;
}

export function encodeHciPacket(payload, sequence) {
  if (!(payload instanceof Uint8Array) || payload.length > 4095) throw new Error('Invalid HCI payload');
  const first = (sequence & 7) | (((sequence + 1) & 7) << 3) | 0xc0;
  const second = 14 | ((payload.length & 15) << 4);
  const third = payload.length >>> 4;
  const data = Uint8Array.of(first, second, third, -(first + second + third) & 255, ...payload);
  const crc = crc16(data);
  const frame = [0xc0];
  for (const byte of [...data, crc & 255, crc >>> 8]) {
    if (byte === 0xc0) frame.push(0xdb, 0xdc);
    else if (byte === 0xdb) frame.push(0xdb, 0xdd);
    else frame.push(byte);
  }
  frame.push(0xc0);
  return Uint8Array.from(frame);
}

export class SlipDecoder {
  constructor() { this.bytes = []; this.escaped = false; this.started = false; }
  push(input) {
    const packets = [];
    for (const byte of input) {
      if (byte === 0xc0) {
        if (this.escaped) throw new Error('Truncated SLIP escape');
        if (this.started && this.bytes.length) packets.push(Uint8Array.from(this.bytes));
        this.started = true; this.bytes = []; continue;
      }
      if (!this.started) continue;
      if (this.escaped) {
        if (byte !== 0xdc && byte !== 0xdd) throw new Error('Invalid SLIP escape');
        this.bytes.push(byte === 0xdc ? 0xc0 : 0xdb); this.escaped = false;
      } else if (byte === 0xdb) this.escaped = true;
      else this.bytes.push(byte);
      if (this.bytes.length > 4101) throw new Error('Oversized HCI packet');
    }
    return packets;
  }
}

function decodeAck(packet) {
  if (packet.length < 4) throw new Error('Truncated HCI acknowledgement');
  if (((packet[0] + packet[1] + packet[2] + packet[3]) & 255) !== 0)
    throw new Error('Invalid HCI acknowledgement header checksum');
  const length = (packet[1] >>> 4) | (packet[2] << 4);
  const hasCrc = !!(packet[0] & 0x40);
  if (packet.length !== 4 + length + (hasCrc ? 2 : 0)) throw new Error('Invalid HCI acknowledgement length');
  if (hasCrc && crc16(packet.subarray(0, -2)) !== (packet.at(-2) | (packet.at(-1) << 8)))
    throw new Error('Invalid HCI acknowledgement CRC16');
  // Pure acknowledgements have packet type zero and no payload. Do not mistake
  // an arbitrary bootloader response or echoed data for accepted firmware.
  if ((packet[1] & 15) !== 0 || length !== 0) throw new Error('Unexpected HCI packet instead of acknowledgement');
  return (packet[0] >>> 3) & 7;
}

export class DfuTransport {
  constructor(port, { ackTimeout = 2000, retries = 2, onWarning = () => {} } = {}) {
    this.ackTimeout = ackTimeout; this.retries = retries; this.sequence = 0;
    this.decoder = new SlipDecoder(); this.pending = null; this.failure = null;
    this.link = new SerialLink(port, {
      onData: bytes => {
        try {
          for (const packet of this.decoder.push(bytes)) {
            const ack = decodeAck(packet);
            if (this.pending && ack === this.pending.expected) this.pending.resolve();
          }
        } catch (error) { this.fail(error); }
      },
      onError: error => this.fail(error),
      onWarning: error => onWarning(error),
    });
  }
  fail(error) { this.failure = error; this.pending?.reject(error); }
  async open() {
    await this.link.open(115200);
    try { await this.link.port.setSignals({ dataTerminalReady: true }); }
    catch (error) { await this.close(); throw error; }
  }
  async send(payload, { signal } = {}) {
    aborted(signal);
    if (this.failure) throw this.failure;
    if (this.pending) throw new Error('A DFU packet is already pending');
    this.sequence = (this.sequence + 1) & 7;
    const frame = encodeHciPacket(payload, this.sequence);
    for (let attempt = 0; attempt <= this.retries; attempt++) {
      let ack;
      try {
        ack = new Promise((resolve, reject) => { this.pending = { resolve, reject, expected: (this.sequence + 1) & 7 }; });
        ack.catch(() => {});
        // Set the waiter before writing: USB devices can ACK before write resolves.
        await this.link.write(frame, { timeout: this.ackTimeout, signal, label: 'DFU write' });
        await bounded(ack, { timeout: this.ackTimeout, signal, label: 'DFU acknowledgement' });
        return;
      } catch (error) {
        aborted(signal);
        if (this.failure || attempt === this.retries || !/acknowledgement timed out/.test(error.message)) throw error;
        // Retransmit the same sequence. The bootloader discards duplicates but
        // repeats its ACK, covering a lost ACK without writing data twice.
      } finally { this.pending = null; }
    }
  }
  async close() {
    this.pending?.reject(new Error('DFU connection closed')); this.pending = null;
    await this.link.close();
  }
}

export async function readDfuPackage(bytes) {
  const zip = await JSZip.loadAsync(bytes, { checkCRC32: true });
  const entries = Object.values(zip.files).filter(file => !file.dir);
  // Application-only packages are tiny metadata plus at most the nRF52840 flash.
  if (entries.length !== 3 || !zip.file('manifest.json')) throw new Error('DFU manifest must describe exactly one application');
  for (const entry of entries) {
    if (entry.unsafeOriginalName && entry.unsafeOriginalName !== entry.name) throw new Error('Unsafe DFU manifest path');
    if (!/^[A-Za-z0-9_.-]+$/.test(entry.name)) throw new Error('Invalid DFU manifest path');
  }
  const metadata = await zip.file('manifest.json').async('string');
  if (metadata.length > 16384) throw new Error('DFU manifest is too large');
  const manifest = JSON.parse(metadata)?.manifest;
  if (!manifest || Object.keys(manifest).some(key => !['application', 'dfu_version'].includes(key)) ||
      !manifest.application || ('dfu_version' in manifest && manifest.dfu_version !== 0.5))
    throw new Error('Only application-only DFU manifests are supported; bootloader and SoftDevice updates are forbidden');
  const { bin_file: bin, dat_file: dat } = manifest.application;
  if (typeof bin !== 'string' || typeof dat !== 'string' || !/^[A-Za-z0-9_.-]+\.bin$/.test(bin) || !/^[A-Za-z0-9_.-]+\.dat$/.test(dat))
    throw new Error('Invalid application file path in DFU manifest');
  if (!zip.file(bin) || !zip.file(dat)) throw new Error('Application files referenced by DFU manifest are missing');
  const [firmware, initPacket] = await Promise.all([zip.file(bin).async('uint8array'), zip.file(dat).async('uint8array')]);
  if (!firmware.length || firmware.length > 1024 * 1024 || !initPacket.length || initPacket.length > 512)
    throw new Error('Invalid application or init-packet size in DFU manifest');
  return { firmware, initPacket };
}

function words(...values) {
  const result = new Uint8Array(values.length * 4); const view = new DataView(result.buffer);
  values.forEach((value, index) => view.setUint32(index * 4, value, true)); return result;
}

export async function enterDfu(port, { signal, onLog = () => {} } = {}) {
  aborted(signal);
  let opened = false;
  try {
    await port.open({ baudRate: 1200 }); opened = true;
    await delay(100, signal);
  } finally { if (opened) await port.close().catch(() => {}); }
  onLog('DFU requested. Select the newly appeared bootloader port before uploading.');
  await delay(1500, signal);
}

export async function flashApplication({ port, firmware, initPacket, onProgress = () => {}, onLog = () => {}, signal }) {
  if (!(firmware instanceof Uint8Array) || !firmware.length || firmware.length > 1024 * 1024 ||
      !(initPacket instanceof Uint8Array) || !initPacket.length || initPacket.length > 512)
    throw new Error('Invalid application DFU image');
  const transport = new DfuTransport(port, { onWarning: error => onLog(`Serial warning: ${error.name}; the packet is retransmitted if needed.`) });
  const pageCount = Math.floor(firmware.length / 4096) + 1;
  const eraseTime = Math.max(500, pageCount * 89.7);
  try {
    aborted(signal); await transport.open(); await delay(100, signal);
    onLog('Sending application-only DFU start.'); onProgress(0);
    await transport.send(words(3, 4, 0, 0, firmware.length), { signal });
    await delay(eraseTime, signal);
    await transport.send(Uint8Array.of(...words(1), ...initPacket, 0, 0), { signal });
    for (let offset = 0; offset < firmware.length; offset += 512) {
      aborted(signal);
      const chunk = firmware.subarray(offset, offset + 512);
      await transport.send(Uint8Array.of(...words(4), ...chunk), { signal });
      // Match the reference tool's allowance for blocked flash page writes.
      if ((offset / 512) % 8 === 0) await delay(103, signal);
      onProgress(Math.min(99, Math.floor((offset + chunk.length) * 99 / firmware.length)));
    }
    await delay(103, signal);
    await transport.send(words(5), { signal });
    onLog('All DFU packets acknowledged. Waiting for bootloader activation.');
    // Dual-bank activation copies the new image to bank 0. Do not reopen/reset
    // during this period; the upstream tool uses these per-page erase/write times.
    await delay(eraseTime + pageCount * 102.4, signal);
    onProgress(100);
    onLog('DFU transfer acknowledged; application startup must be checked after reconnecting.');
  } finally { await transport.close(); }
}
