import test from 'node:test';
import assert from 'node:assert/strict';
import { ConsoleSession } from '../src/serial.js';

function serialFake(onWrite = () => {}) {
  let input;
  const writes = [];
  const port = {
    opens: [], signals: [], closed: false,
    async open(options) {
      this.opens.push(options);
      this.readable = new ReadableStream({ start(c) { input = c; } });
      this.writable = new WritableStream({ write(bytes) {
        const text = new TextDecoder().decode(bytes); writes.push(text); onWrite(text, port);
      } });
    },
    async setSignals(value) { this.signals.push(value); },
    async close() { this.closed = true; this.readable = null; this.writable = null; },
    emit(text) { input.enqueue(typeof text === 'string' ? new TextEncoder().encode(text) : text); },
    disconnect() { input.close(); },
    writes,
  };
  return port;
}

test('commands require an exact prompt, handle partial reads, and serialize replies', async () => {
  const port = serialFake((line, p) => {
    if (line === 'rnc-config\n') { p.emit('\r\nreticulum-c provisioning console\r\nrn'); p.emit('c> '); }
    else { setTimeout(() => p.emit(`${line.trim()}\r\nok\r\nrnc> `), 5); }
  });
  const session = new ConsoleSession();
  await session.connect(port);
  await assert.rejects(session.command('save'), /console|prompt/i);
  await session.enterConsole();
  const replies = await Promise.all([session.command('get'), session.command('save')]);
  assert.match(replies[0], /ok/);
  assert.deepEqual(port.writes.slice(-2), ['get\n', 'save\n']);
  assert.equal(port.opens[0].baudRate, 115200);
  assert.ok(port.signals.some(s => s.dataTerminalReady === true));
  await session.close();
  assert.equal(port.closed, true);
});

test('embedded prompt text cannot authorize configuration writes', async () => {
  const port = serialFake((line, p) => p.emit('binary says rnc> '));
  const session = new ConsoleSession();
  await session.connect(port);
  await assert.rejects(session.enterConsole({ timeout: 35 }), /timed out|timeout/i);
  await assert.rejects(session.command('set mode wifi'), /console|connect|prompt/i);
  assert.ok(port.writes.every(w => w === 'rnc-config\n'));
  await session.close();
});

test('HDLC input and disconnect revoke console state', async () => {
  const port = serialFake((line, p) => { if (line === 'rnc-config\n') p.emit('\nrnc> '); });
  const session = new ConsoleSession();
  await session.connect(port);
  await session.enterConsole();
  const reply = session.command('get', { timeout: 100 });
  await new Promise(r => setTimeout(r, 1));
  port.emit(new Uint8Array([0xc0, 1, 2, 0xc0]));
  await assert.rejects(reply, /binary|HDLC/i);
  assert.equal(session.inConsole, false);
  await session.close();
});

test('USB disconnect rejects pending command and revokes command permission', async () => {
  const port = serialFake((line, p) => {
    if (line === 'rnc-config\n') p.emit('\nrnc> ');
    else p.disconnect();
  });
  const session = new ConsoleSession();
  await session.connect(port); await session.enterConsole();
  await assert.rejects(session.command('get'), /disconnect/i);
  assert.equal(session.inConsole, false);
  await assert.rejects(session.command('save'), /prompt|console/i);
  await session.close();
});

test('device errors reject and password echoes never reach logs', async () => {
  const logs = [];
  const port = serialFake((line, p) => {
    if (line === 'rnc-config\n') p.emit('\nrnc> ');
    else p.emit(`${line.trim()}\r\nerror: invalid key\r\nrnc> `);
  });
  const session = new ConsoleSession({ onLog: line => logs.push(line) });
  await session.connect(port); await session.enterConsole();
  await assert.rejects(session.command('set password private-passphrase'), error => {
    assert.doesNotMatch(error.message, /private-passphrase/); return /error:/.test(error.message);
  });
  assert.doesNotMatch(logs.join('\n'), /private-passphrase/);
  await session.close();
});

test('cancelled and timed out commands release port locks', async () => {
  for (const cancel of [false, true]) {
    const port = serialFake((line, p) => { if (line === 'rnc-config\n') p.emit('\nrnc> '); });
    const session = new ConsoleSession();
    await session.connect(port); await session.enterConsole();
    const controller = new AbortController();
    const result = session.command('get', { timeout: 25, signal: controller.signal });
    if (cancel) setTimeout(() => controller.abort(), 2);
    await assert.rejects(result, cancel ? /abort/i : /timed out|timeout/i);
    await session.close();
    assert.equal(port.closed, true);
  }
});

test('UTF-8 settings survive split multibyte reads and overlong lines are refused locally', async () => {
  const port = serialFake((line, p) => {
    if (line === 'rnc-config\n') p.emit('\nrnc> ');
    else {
      const bytes = new TextEncoder().encode(`${line}\r\nok\r\nrnc> `);
      const split = bytes.indexOf(0xc3) + 1;
      p.emit(bytes.slice(0, split)); p.emit(bytes.slice(split));
    }
  });
  const session = new ConsoleSession();
  await session.connect(port); await session.enterConsole();
  assert.match(await session.command('set ssid café'), /café/);
  const before = port.writes.length;
  await assert.rejects(session.command('set ssid ' + 'a'.repeat(151)), /159|long|byte/i);
  assert.equal(port.writes.length, before);
  await session.close();
});

test('reboot waits for firmware acknowledgement and releases the port', async () => {
  const port = serialFake((line, p) => {
    if (line === 'rnc-config\n') p.emit('\nrnc> ');
    else if (line === 'reboot\n') { p.emit('reboot\r\nreboot'); p.emit('ing\r\n'); }
  });
  const states = [];
  const session = new ConsoleSession({ onState: state => states.push(state) });
  await session.connect(port); await session.enterConsole();
  await session.reboot();
  assert.equal(port.closed, true);
  assert.equal(session.inConsole, false);
  assert.equal(states.at(-1), 'disconnected');
});

test('native HDLC delimiter rejects entry and ESP reset releases BOOT before reset release', async () => {
  const binary = serialFake((line, p) => p.emit(Uint8Array.of(0x7e, 0x41, 0x7e)));
  const session = new ConsoleSession();
  await session.connect(binary);
  await assert.rejects(session.enterConsole(), /HDLC|binary/i);
  const text = serialFake((line, p) => p.emit('\nrnc> '));
  await session.connect(text);
  await session.enterConsole({ reset: true });
  const resetRelease = text.signals.find(s => s.requestToSend === false);
  assert.equal(resetRelease.dataTerminalReady, false);
  await session.close();
});
