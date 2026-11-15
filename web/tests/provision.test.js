import test from 'node:test';
import assert from 'node:assert/strict';
import { connectConsole } from '../src/provision.js';

const ids = { usbVendorId: 0x239a, usbProductId: 0x8029 };
function fakePort(onWrite) {
  let input;
  return {
    writes: [], closed: false, getInfo: () => ids,
    async open() {
      this.readable = new ReadableStream({ start(c) { input = c; } });
      this.writable = new WritableStream({ write: bytes => { const t = new TextDecoder().decode(bytes); this.writes.push(t); onWrite(t, this, input); } });
    },
    async setSignals() {}, async close() { this.closed = true; this.readable = null; this.writable = null; },
  };
}

test('console entry survives the board resetting and re-enumerating', async () => {
  const old = fakePort((line, p, input) => { try { input.close(); } catch { /* already closed */ } });
  const fresh = fakePort((line, p, input) => { if (line === 'rnc-config\n') input.enqueue(new TextEncoder().encode('\r\nrnc> ')); });
  let listed = 0;
  const serial = { async getPorts() { return ++listed < 3 ? [] : [fresh]; } };
  const logs = [];
  const session = await connectConsole({ serial, port: old, timeout: 5000, onLog: l => logs.push(l) });
  assert.equal(session.inConsole, true);
  assert.ok(old.closed);
  assert.ok(fresh.writes.includes('rnc-config\n'));
  assert.ok(logs.some(l => /reappear/.test(l)));
  await session.close();
});

test('a port that stays silent is retried only until the overall deadline', async () => {
  const silent = fakePort(() => {});
  const started = Date.now();
  await assert.rejects(connectConsole({ serial: { async getPorts() { return [silent]; } }, port: silent, timeout: 1200 }), /timed out|prompt/i);
  assert.ok(Date.now() - started < 4000);
});

test('abort stops reconnecting and releases the port', async () => {
  const dead = fakePort((l, p, input) => { try { input.close(); } catch { /* closed */ } });
  const controller = new AbortController();
  setTimeout(() => controller.abort(new DOMException('Connection cancelled', 'AbortError')), 300);
  await assert.rejects(connectConsole({ serial: { async getPorts() { return [dead]; } }, port: dead, timeout: 20000, signal: controller.signal }), /cancel|abort/i);
  assert.ok(dead.closed);
});
