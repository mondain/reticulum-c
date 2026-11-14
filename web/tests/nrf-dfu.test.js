import test from 'node:test';
import assert from 'node:assert/strict';
import JSZip from 'jszip';
import { crc16, encodeHciPacket, SlipDecoder, DfuTransport, readDfuPackage, flashApplication, enterDfu } from '../src/nrf-dfu.js';
import { downloadVerified, flashEsp, resetEspApplication } from '../src/flash.js';
import { createHash } from 'node:crypto';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { execFile } from 'node:child_process';

test('CRC16 and HCI frame match independently checked Nordic vectors', () => {
  assert.equal(crc16(new TextEncoder().encode('123456789')), 0x29b1);
  assert.deepEqual([...encodeHciPacket(Uint8Array.of(5, 0, 0, 0), 1)],
    [192, 209, 78, 0, 225, 5, 0, 0, 0, 116, 130, 192]);
});

test('SLIP decoder handles split escapes and rejects malformed escapes', () => {
  const decoder = new SlipDecoder();
  assert.deepEqual(decoder.push(Uint8Array.of(192, 219)), []);
  assert.deepEqual(decoder.push(Uint8Array.of(220, 219, 221, 192)), [Uint8Array.of(192, 219)]);
  assert.throws(() => decoder.push(Uint8Array.of(192, 219, 1, 192)), /escape/i);
});

function dfuPort(reply) {
  let input;
  const writes = [];
  return {
    closed: false, writes,
    async open() {
      this.readable = new ReadableStream({ start(c) { input = c; } });
      this.writable = new WritableStream({ write(bytes) {
        writes.push(bytes.slice());
        reply?.(bytes, { emit: bytes => input.enqueue(bytes), attempt: writes.length });
      } });
    },
    async setSignals() {},
    async close() { this.closed = true; this.readable = null; this.writable = null; },
  };
}

// Empty ACK header with ack_nr=2, no CRC, header sum=0; target expects sequence 2 next.
const ack2 = Uint8Array.of(192, 16, 0, 0, 240, 192);

test('DFU requires a valid matching ACK and handles partial ACK input', async () => {
  const port = dfuPort((_, io) => { io.emit(ack2.slice(0, 3)); io.emit(ack2.slice(3)); });
  const transport = new DfuTransport(port, { ackTimeout: 30 });
  await transport.open();
  await transport.send(Uint8Array.of(5, 0, 0, 0));
  await transport.close();
  assert.equal(port.closed, true);
});

test('DFU retries the identical sequence on wrong ACK and fails after a bounded wait', async () => {
  const wrong = Uint8Array.of(192, 8, 0, 0, 248, 192);
  const port = dfuPort((_, io) => io.emit(wrong));
  const transport = new DfuTransport(port, { ackTimeout: 12, retries: 2 });
  await transport.open();
  await assert.rejects(transport.send(Uint8Array.of(5, 0, 0, 0)), /acknowledg/i);
  assert.equal(port.writes.length, 3);
  assert.deepEqual(port.writes[0], port.writes[2]);
  await transport.close();
  assert.equal(port.closed, true);
});

test('DFU rejects invalid ACK checksum and cancellation releases locks', async () => {
  const port = dfuPort((_, io) => io.emit(Uint8Array.of(192, 16, 0, 0, 1, 192)));
  const transport = new DfuTransport(port, { ackTimeout: 20 });
  await transport.open();
  await assert.rejects(transport.send(Uint8Array.of(1)), /checksum/i);
  await transport.close();
  const silent = dfuPort();
  const cancelled = new DfuTransport(silent, { ackTimeout: 100 });
  await cancelled.open();
  const controller = new AbortController();
  const sending = cancelled.send(Uint8Array.of(1), { signal: controller.signal });
  setTimeout(() => controller.abort(), 2);
  await assert.rejects(sending, /abort/i);
  await cancelled.close();
  assert.equal(silent.closed, true);
});

async function packageZip(manifest) {
  const zip = new JSZip();
  zip.file('manifest.json', JSON.stringify({ manifest }));
  zip.file('firmware.dat', Uint8Array.of(1, 2));
  zip.file('firmware.bin', Uint8Array.of(1, 2, 3, 4));
  return zip.generateAsync({ type: 'uint8array' });
}

test('DFU ZIP validates application-only manifest before opening any port', async () => {
  const application = { bin_file: 'firmware.bin', dat_file: 'firmware.dat' };
  const image = await readDfuPackage(await packageZip({ application }));
  assert.equal(image.firmware.length, 4);
  // adafruit-nrfutil's standard manifest carries this package-version metadata.
  assert.equal((await readDfuPackage(await packageZip({ application, dfu_version: 0.5 }))).firmware.length, 4);
  for (const manifest of [{}, { application, bootloader: {} }, { application: { ...application, bin_file: '../other.bin' } }]) {
    await assert.rejects(readDfuPackage(await packageZip(manifest)), /application|manifest|path/i);
  }
});

test('firmware downloads require the catalog byte size and SHA-256', async () => {
  const original = globalThis.fetch;
  const bytes = Uint8Array.of(1, 2, 3, 4);
  const file = { path: 'board/firmware.bin', size: 4, sha256: createHash('sha256').update(bytes).digest('hex') };
  let requested;
  globalThis.fetch = async url => { requested = url.href; return new Response(bytes); };
  try {
    assert.deepEqual(await downloadVerified(file, 'https://example.com/repo/firmware/catalog.json'), bytes);
    assert.equal(requested, 'https://example.com/repo/firmware/board/firmware.bin');
    await assert.rejects(downloadVerified({ ...file, sha256: '0'.repeat(64) }, 'https://example.com/'), /SHA-256|hash/i);
    await assert.rejects(downloadVerified({ ...file, size: 3 }, 'https://example.com/'), /size/i);
    await assert.rejects(downloadVerified({ ...file, path: '../private.bin' }, 'https://example.com/'), /path/i);
  } finally { globalThis.fetch = original; }
});

test('ESP verifies every firmware part before opening the device or writing flash', async () => {
  const original = globalThis.fetch;
  let opens = 0;
  globalThis.fetch = async () => new Response(Uint8Array.of(1, 2, 3, 4));
  try {
    await assert.rejects(flashEsp({
      port: { async open() { opens++; } }, baseUrl: 'https://example.com/catalog.json',
      eraseAll: true, confirmErase: true,
      board: { family: 'esp32', chip: 'ESP32', parts: [{ offset: 4096, path: 'firmware.bin', size: 4, sha256: '0'.repeat(64) }] },
    }), /SHA-256|hash/i);
    assert.equal(opens, 0);
  } finally { globalThis.fetch = original; }
});

test('a lost ACK retries the packet and then continues with the next sequence', async () => {
  const port = dfuPort((_, io) => {
    if (io.attempt === 2) io.emit(ack2);
    if (io.attempt === 3) io.emit(Uint8Array.of(192, 24, 0, 0, 232, 192));
  });
  const transport = new DfuTransport(port, { ackTimeout: 12 });
  await transport.open();
  await transport.send(Uint8Array.of(3));
  await transport.send(Uint8Array.of(1));
  assert.equal(port.writes.length, 3);
  assert.deepEqual(port.writes[0], port.writes[1]);
  assert.notDeepEqual(port.writes[1], port.writes[2]);
  await transport.close();
});

test('full application DFU acknowledges start, init, every data chunk and stop before completion', async () => {
  const operations = [], sequences = [], progress = [];
  const decoder = new SlipDecoder();
  const port = dfuPort((frame, io) => {
    const [packet] = decoder.push(frame);
    const sequence = packet[0] & 7;
    sequences.push(sequence);
    operations.push(new DataView(packet.buffer, packet.byteOffset + 4, 4).getUint32(0, true));
    const ack = ((sequence + 1) & 7) << 3;
    io.emit(Uint8Array.of(192, ack, 0, 0, -ack & 255, 192));
  });
  await flashApplication({ port, firmware: new Uint8Array(1028), initPacket: Uint8Array.of(1, 2), onProgress: p => progress.push(p) });
  assert.deepEqual(operations, [3, 1, 4, 4, 4, 5]);
  assert.deepEqual(sequences, [1, 2, 3, 4, 5, 6]);
  assert.equal(progress.at(-1), 100);
  assert.ok(progress.slice(0, -1).every(value => value < 100));
  assert.equal(port.closed, true);
});

test('1200-baud DFU touch closes application port even when cancelled', async () => {
  const port = dfuPort();
  const controller = new AbortController();
  const entering = enterDfu(port, { signal: controller.signal });
  setTimeout(() => controller.abort(), 2);
  await assert.rejects(entering, /abort/i);
  assert.equal(port.closed, true);
});

test('application DFU cancellation closes the port and never reports completion', async () => {
  const port = dfuPort((_, io) => io.emit(ack2));
  const controller = new AbortController();
  const progress = [];
  const result = flashApplication({ port, firmware: Uint8Array.of(1, 2, 3, 4), initPacket: Uint8Array.of(1),
    onProgress: p => progress.push(p), signal: controller.signal });
  setTimeout(() => controller.abort(), 120);
  await assert.rejects(result, /abort/i);
  assert.equal(port.closed, true);
  assert.ok(progress.every(p => p < 100));
});

test('ESP application reset holds BOOT released and pulses reset before release', async () => {
  const signals = [];
  const transport = { async setDTR(value) { signals.push(['DTR', value]); }, async setRTS(value) { signals.push(['RTS', value]); } };
  await resetEspApplication(transport);
  assert.deepEqual(signals, [['DTR', false], ['RTS', true], ['RTS', false]]);
});

test('ESP factory erase requires explicit confirmation before any download or port access', async () => {
  await assert.rejects(flashEsp({
    port: {}, board: { family: 'esp32', chip: 'ESP32', parts: [{}] }, eraseAll: true,
  }), /confirm/i);
});

test('ESP defaults to preserving flash, honors confirmed factory erase, and rejects the wrong chip before erase', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'rnc-esp-api-test-'));
  const fake = pathToFileURL(join(dir, 'esp.mjs')).href;
  try {
    // Replace the external bootloader boundary, retaining the actual download,
    // chip check, write options, MD5 callback, reset and cleanup implementation.
    await writeFile(join(dir, 'esp.mjs'), `
      export class Transport { constructor(device) { this.device = device; } async setDTR(v) {} async setRTS(v) {} }
      export class ESPLoader {
        constructor(options) { this.transport = options.transport; }
        async main() { this.chip = { CHIP_NAME: process.env.RNC_TEST_CHIP }; }
        async writeFlash(options) { globalThis.observed.push({ eraseAll: options.eraseAll, address: options.fileArray[0].address, md5: options.calculateMD5Hash('abc') }); }
      }
    `);
    await writeFile(join(dir, 'loader.mjs'), `export async function resolve(specifier, context, next) { if (specifier === 'esptool-js') return { url: ${JSON.stringify(fake)}, shortCircuit: true }; return next(specifier, context); }`);
    const production = new URL('../src/flash.js', import.meta.url).href;
    const hash = createHash('sha256').update(Uint8Array.of(1, 2, 3, 4)).digest('hex');
    await writeFile(join(dir, 'run.mjs'), `
      import { writeFileSync } from 'node:fs';
      import { flashEsp } from ${JSON.stringify(production)};
      globalThis.observed = [];
      globalThis.fetch = async () => new Response(Uint8Array.of(1,2,3,4));
      const board = { family:'esp32', chip:'ESP32', parts:[{path:'app.bin',offset:65536,size:4,sha256:${JSON.stringify(hash)}}] };
      let error;
      try { await flashEsp({port:{},board,baseUrl:'https://example.test/catalog.json',...JSON.parse(process.env.RNC_TEST_OPTIONS)}); }
      catch (e) { error=e.message; }
      writeFileSync(process.env.RNC_TEST_RESULT, JSON.stringify({observed:globalThis.observed,error}));
    `);
    const run = async (chip, options) => {
      await promisify(execFile)(process.execPath, ['--experimental-loader', join(dir, 'loader.mjs'), join(dir, 'run.mjs')], {
        env: { ...process.env, RNC_TEST_CHIP: chip, RNC_TEST_OPTIONS: JSON.stringify(options), RNC_TEST_RESULT: join(dir, 'result.json') },
      });
      return JSON.parse(await readFile(join(dir, 'result.json'), 'utf8'));
    };
    assert.deepEqual((await run('ESP32', {})).observed, [{ eraseAll: false, address: 65536, md5: '900150983cd24fb0d6963f7d28e17f72' }]);
    assert.equal((await run('ESP32', { eraseAll: true, confirmErase: true })).observed[0].eraseAll, true);
    const wrong = await run('ESP32-S3', { eraseAll: true, confirmErase: true });
    assert.deepEqual(wrong.observed, []);
    assert.match(wrong.error, /Wrong chip/);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('a stalled serial write fails without retransmitting a partial frame', async () => {
  const writes = [];
  const port = {
    async open() {
      this.readable = new ReadableStream({ start() {} });
      this.writable = new WritableStream({ write(bytes) { writes.push(bytes); return new Promise(() => {}); } });
    },
    async setSignals() {}, async close() { this.readable = null; this.writable = null; },
  };
  const transport = new DfuTransport(port, { ackTimeout: 20, retries: 2 });
  await transport.open();
  await assert.rejects(transport.send(Uint8Array.of(5, 0, 0, 0)), /DFU write timed out/);
  assert.equal(writes.length, 1);
  await transport.close().catch(() => {});
});
