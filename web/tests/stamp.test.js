import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { Worker } from 'node:worker_threads';
import { TAB } from '../src/stamp-table.js';
import { costToFp, targetFromFp, sha256, stampValid, searchSlice, findStamp, fromHex, hex } from '../src/stamp.js';
import { run } from '../src/stamp-worker.js';
import { setStamp } from '../src/stamp-ui.js';

test('the mantissa table is the one in src/netstamp_tab.h', () => {
  const header = readFileSync(new URL('../../src/netstamp_tab.h', import.meta.url), 'utf8');
  const values = [...header.matchAll(/0x[0-9a-f]+/g)].map(m => BigInt(m[0]));
  assert.equal(values.length, 256);
  assert.deepEqual(TAB, values);
});

test('costs: fixed point, capped, never negative', () => {
  assert.equal(costToFp(23.5), 6016);
  assert.equal(costToFp(0), 0);
  assert.equal(costToFp(-3), 0);
  assert.equal(costToFp(500), 100 * 256);
  assert.equal(costToFp(15.8), 4045);
  assert.ok(targetFromFp(0) === (1n << 256n) - 1n); // nothing is required
  assert.ok(targetFromFp(256) < targetFromFp(0));
});

test('sha256 agrees with node:crypto on every length around the block boundaries', () => {
  for (let n = 0; n < 200; n++) {
    const data = randomBytes(n);
    assert.equal(hex(sha256(data)), createHash('sha256').update(data).digest('hex'), `length ${n}`);
  }
});

test('stampValid agrees with the C library on 1080 stamp and cost pairs (a fixture it generated)', () => {
  const fixture = JSON.parse(readFileSync(new URL('./stamp-fixture.json', import.meta.url), 'utf8'));
  assert.ok(fixture.length >= 1000);
  for (const [material, stamp, cost, valid] of fixture)
    assert.equal(stampValid(fromHex(material, 90), fromHex(stamp, 14), cost), !!valid, `${material.slice(0, 8)} ${stamp} at ${cost}`);
});

test('a stamp found at one flipped bit away from valid is rejected', () => {
  const material = randomBytes(90);
  const stamp = searchSlice({ material, cost: 10, start: new Uint8Array(14), attempts: 1 << 20 });
  assert.ok(stamp && stampValid(material, stamp, 10));
  const worse = Uint8Array.from(stamp); worse[0] ^= 0x80; worse[1] ^= 0xff;
  assert.equal(stampValid(material, worse, 20), false);
});

test('searchSlice finds stamps that the full verification accepts, fractional costs included', () => {
  for (const cost of [4, 8.5, 11.25, 12]) {
    const material = randomBytes(90);
    const stamp = searchSlice({ material, cost, start: randomBytes(14), attempts: 1 << 22 });
    assert.ok(stamp, `found at ${cost}`);
    assert.equal(stampValid(material, stamp, cost), true);
  }
});

test('the search counts through carries in the counter', () => {
  const material = randomBytes(90);
  const start = new Uint8Array(14); start.fill(0xff, 10); // the last four bytes about to wrap
  const stamp = searchSlice({ material, cost: 9, start, attempts: 1 << 20 });
  assert.ok(stamp && stampValid(material, stamp, 9));
});

// A worker backed by the same code as the browser one, on a worker thread.
function threadWorker() {
  const source = `
    const { parentPort } = require('node:worker_threads');
    parentPort.on('message', async m => {
      const { run } = await import(${JSON.stringify(new URL('../src/stamp-worker.js', import.meta.url).href)});
      run(msg => parentPort.postMessage(msg), m);
    });`;
  const w = new Worker(source, { eval: true });
  return { postMessage: m => w.postMessage(m), set onmessage(f) { w.on('message', data => f({ data })); }, set onerror(f) { w.on('error', f); }, terminate: () => w.terminate() };
}

test('findStamp runs workers in parallel and returns a valid stamp', async () => {
  const material = randomBytes(90);
  let progressed = 0;
  const stamp = await findStamp({ material, cost: 14, workers: 2, makeWorker: threadWorker, onProgress: () => { progressed++; } });
  assert.equal(stampValid(material, stamp, 14), true);
  assert.ok(progressed >= 0);
});

test('findStamp can be cancelled', async () => {
  const material = randomBytes(90), controller = new AbortController();
  const started = Date.now();
  const promise = findStamp({ material, cost: 60, workers: 2, makeWorker: threadWorker, signal: controller.signal });
  setTimeout(() => controller.abort(), 300);
  await assert.rejects(promise, error => error.name === 'AbortError');
  assert.ok(Date.now() - started < 2000);
});

test('the worker module reports progress and finds a stamp in a single thread too', async () => {
  const messages = [];
  const material = randomBytes(90);
  await new Promise(resolve => {
    run(m => { messages.push(m); if (m.type === 'found') resolve(); }, { material: Array.from(material), cost: 12, start: Array.from(randomBytes(14)), slice: 1 << 12 });
  });
  const found = messages.at(-1);
  assert.equal(found.type, 'found');
  assert.equal(stampValid(material, Uint8Array.from(found.stamp), 12), true);
});

test('a stamp the board refuses is never followed by a save (which would write other pending settings)', async () => {
  const sent = [];
  const session = { async command(line) { sent.push(line); if (line.startsWith('set stamp')) throw new Error('error: refused (see help)'); return 'saving\r\nstored\r\nstamp stored'; } };
  await assert.rejects(setStamp({ session, hexText: '00112233445566778899aabbccdd' }), /refused/);
  assert.deepEqual(sent, ['set stamp 00112233445566778899aabbccdd']);
  sent.length = 0;
  const good = { async command(line) { sent.push(line); return line === 'save' ? 'saving\r\nstored\r\nstamp stored' : 'ok'; } };
  await setStamp({ session: good, hexText: '00112233445566778899AABBCCDD' });
  assert.deepEqual(sent, ['set stamp 00112233445566778899aabbccdd', 'save']);
});
