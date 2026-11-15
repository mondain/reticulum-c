const encoder = new TextEncoder();

export function aborted(signal) {
  if (signal?.aborted) throw signal.reason instanceof Error ? signal.reason : new DOMException('Operation aborted', 'AbortError');
}

export function bounded(promise, { timeout = 5000, signal, label = 'Serial operation' } = {}) {
  aborted(signal);
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => finish(reject, new Error(`${label} timed out`)), timeout);
    const onAbort = () => finish(reject, signal.reason instanceof Error ? signal.reason : new DOMException('Operation aborted', 'AbortError'));
    function finish(fn, value) {
      clearTimeout(timer); signal?.removeEventListener('abort', onAbort); fn(value);
    }
    signal?.addEventListener('abort', onAbort, { once: true });
    Promise.resolve(promise).then(v => finish(resolve, v), e => finish(reject, e));
  });
}

export function delay(ms, signal) {
  aborted(signal);
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { signal?.removeEventListener('abort', cancel); resolve(); }, ms);
    const cancel = () => {
      clearTimeout(timer); signal.removeEventListener('abort', cancel);
      reject(signal.reason instanceof Error ? signal.reason : new DOMException('Operation aborted', 'AbortError'));
    };
    signal?.addEventListener('abort', cancel, { once: true });
  });
}

const RECOVERABLE_READ_ERRORS = new Set(['BufferOverrunError', 'BreakError', 'FramingError', 'ParityError']);

// Owns the Web Serial locks. The reader runs continuously so fragmented replies and
// disconnects are observed even when the caller is between commands.
export class SerialLink {
  constructor(port, { onData = () => {}, onError = () => {}, onWarning = () => {} } = {}) {
    this.port = port; this.onData = onData; this.onError = onError; this.onWarning = onWarning;
    this.reader = null; this.writer = null; this.opened = false; this.closing = false;
  }
  async open(baudRate = 115200) {
    try {
      await this.port.open({ baudRate, bufferSize: 65536, flowControl: 'none' });
      this.opened = true;
      if (!this.port.readable || !this.port.writable) throw new Error('Serial port has no readable/writable streams');
      this.reader = this.port.readable.getReader(); this.writer = this.port.writable.getWriter();
      this.pump = this.readLoop();
    } catch (error) { await this.close(); throw error; }
  }
  async readLoop() {
    // Overrun, framing, parity and break errors are not fatal in Web Serial: the
    // port replaces its readable stream and keeps going. Anything else ends the link.
    let recovered = 0;
    try {
      for (;;) {
        try {
          while (!this.closing) {
            const { value, done } = await this.reader.read();
            if (done) { if (!this.closing) throw new Error('Serial device disconnected'); return; }
            if (value?.length) this.onData(value);
          }
          return;
        } catch (error) {
          if (this.closing || !RECOVERABLE_READ_ERRORS.has(error?.name) || !this.port.readable || ++recovered > 50) throw error;
          try { this.reader.releaseLock(); } catch { /* The failed stream is already released. */ }
          this.reader = this.port.readable.getReader();
          this.onWarning(error);
        }
      }
    } catch (error) {
      if (!this.closing) { this.onError(error); void this.close(); }
    } finally {
      try { this.reader?.releaseLock(); } catch { /* Already released. */ }
      this.reader = null;
    }
  }
  async write(bytes, options) {
    if (!this.writer || this.closing) throw new Error('Serial port is disconnected');
    await bounded(this.writer.write(bytes), options);
  }
  async close() {
    if (this.closePromise) return this.closePromise;
    this.closing = true;
    this.closePromise = (async () => {
      // A wedged device can leave a write or read pending forever; never wait for it.
      const quick = promise => Promise.race([Promise.resolve(promise).catch(() => {}), delay(1500)]);
      await quick(this.reader?.cancel());
      await quick(this.pump);
      if (this.writer) {
        await quick(this.writer.abort());
        try { this.writer.releaseLock(); } catch { /* A write is still pending on a wedged device. */ }
        this.writer = null;
      }
      if (this.opened) await quick(this.port.close());
      this.opened = false;
    })();
    return this.closePromise;
  }
}

export class ConsoleSession {
  constructor({ onLog = () => {}, onState = () => {} } = {}) {
    this.onLog = onLog; this.onState = onState; this._ready = false;
    this._queue = Promise.resolve(); this.buffer = ''; this.waiter = null; this.failure = null;
  }
  get connected() { return !!this.link?.opened && !this.link.closing; }
  get inConsole() { return this._ready && this.connected; }
  async connect(port) {
    await this.close();
    this.failure = null; this.buffer = ''; this._ready = false; this._entered = false; this.lastRx = 0;
    this.decoder = new TextDecoder('utf-8', { fatal: true });
    this.link = new SerialLink(port, {
      onData: bytes => this.receive(bytes), onError: error => this.fail(error),
      onWarning: error => this.onLog(`Serial warning: ${error.name}`),
    });
    await this.link.open();
    try { await port.setSignals({ dataTerminalReady: true }); }
    catch (error) { await this.close(); throw error; }
    this.onState('connected');
  }
  receive(bytes) {
    this.lastRx = Date.now();
    if (!this._entered) {
      // Before the first prompt the board may still be running the node, which streams
      // HDLC frames (0x7e/0xc0 delimited binary), or printing boot text. Keep only
      // plain text; any other byte is a frame boundary, so text cannot join across it.
      for (const byte of bytes) {
        if (byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte < 127)) this.buffer += String.fromCharCode(byte);
        else this.buffer = '';
      }
      if (this.buffer.length > 4096) this.buffer = this.buffer.slice(-256);
    } else {
      // Once the console is up, HDLC or non-text bytes mean the node has started.
      if ([...bytes].some(b => b === 0xc0 || (b < 32 && ![8, 9, 10, 13, 27].includes(b)) || b === 127)) {
        this.fail(new Error('Binary/HDLC stream detected. Reset the board and reconnect to enter the console.'));
        void this.link?.close(); return;
      }
      try { this.buffer += this.decoder.decode(bytes, { stream: true }); }
      catch {
        this.fail(new Error('Binary/HDLC stream detected. Reset the board and reconnect to enter the console.'));
        void this.link?.close(); return;
      }
      if (this.buffer.length > 32768) {
        this.fail(new Error('Console response exceeded its size limit')); void this.link?.close(); return;
      }
    }
    if (this.waiter?.kind === 'reboot' && /(?:^|\r?\n)rebooting\r?\n/.test(this.buffer)) {
      const waiter = this.waiter; this.waiter = null; waiter.resolve(this.buffer); this.buffer = ''; return;
    }
    const match = /(?:^|\r?\n)rnc> ?$/.exec(this.buffer);
    if (match) {
      this._ready = true; this._entered = true;
      if (this.waiter) {
        const response = this.buffer.slice(0, match.index); this.buffer = '';
        const waiter = this.waiter; this.waiter = null; waiter.resolve(response);
      }
    }
  }
  fail(error) {
    this.failure = error; this._ready = false; this._entered = false;
    if (this.waiter) { const waiter = this.waiter; this.waiter = null; waiter.reject(error); }
    this.onState('disconnected');
  }
  waitPrompt({ timeout, signal, kind = 'prompt' }) {
    if (this.waiter) throw new Error('A console reply is already pending');
    const pending = new Promise((resolve, reject) => { this.waiter = { resolve, reject, kind }; });
    return bounded(pending, { timeout, signal, label: 'Waiting for rnc> prompt' }).finally(() => { this.waiter = null; });
  }
  // Wait until the device has been silent for `quiet` ms. Entry lines still in flight
  // (or held in a USB-UART bridge across a reset) are answered by the console with
  // "error: unknown command" and a fresh prompt; those replies must be consumed here,
  // or they would be taken for the answer to the first real command.
  async settle({ quiet, signal, limit = 3000 }) {
    const started = Date.now();
    while (!this.failure && Date.now() - this.lastRx < quiet && Date.now() - started < limit)
      await delay(Math.min(50, quiet), signal);
    if (this.failure) throw this.failure;
    this.buffer = ''; this._ready = true;
  }
  async enterConsole({ signal, timeout = 15000, quiet = 300 } = {}) {
    if (!this.connected) throw new Error('Connect the serial port first');
    if (this.inConsole) return '';
    aborted(signal);
    this.buffer = '';
    try {
      this.onLog('Waiting for provisioning console. Tap RESET now if needed.');
      const prompt = this.waitPrompt({ timeout, signal });
      // Suppress an unhandled rejection while a serial write is in flight.
      prompt.catch(() => {});
      let finished = false;
      prompt.then(() => { finished = true; }, () => { finished = true; });
      while (!finished && !this.failure) {
        await this.link.write(encoder.encode('rnc-config\n'), { timeout: 1000, signal });
        await Promise.race([prompt.then(() => {}, () => {}), delay(150, signal)]);
      }
      const reply = await prompt;
      await this.settle({ quiet, signal });
      this.onState('console'); this.onLog('Provisioning console ready.'); return reply;
    } catch (error) { this.fail(error); await this.close(); throw error; }
  }
  command(line, { timeout = 5000, signal } = {}) {
    const task = this._queue.then(() => this.runCommand(line, { timeout, signal }));
    this._queue = task.catch(() => {}); return task;
  }
  async runCommand(line, { timeout, signal }) {
    if (!this.inConsole) throw new Error('The rnc> console prompt must be detected before commands can be sent');
    if (typeof line !== 'string' || !line || /[\x00-\x1f\x7f]/.test(line) || encoder.encode(line).length > 159)
      throw new Error('Console command must be one text line of at most 159 UTF-8 bytes');
    aborted(signal);
    this._ready = false; this.buffer = '';
    const prompt = this.waitPrompt({ timeout, signal }); prompt.catch(() => {});
    let reply;
    try {
      await this.link.write(encoder.encode(`${line}\n`), { timeout, signal });
      reply = await prompt;
    } catch (error) { this.fail(error); await this.close(); throw error; }
    const password = /^set\s+password\s+(.+)$/i.exec(line)?.[1];
    if (password) reply = reply.split(password).join('[redacted]');
    if (/(?:^|\r?\n)\s*error\s*:/i.test(reply)) throw new Error(reply.trim());
    return reply.trim();
  }
  reboot({ timeout = 5000, signal } = {}) {
    const task = this._queue.then(async () => {
      if (!this.inConsole) throw new Error('The rnc> console prompt must be detected before reboot');
      this._ready = false; this.buffer = '';
      const reply = this.waitPrompt({ timeout, signal, kind: 'reboot' }); reply.catch(() => {});
      try {
        await this.link.write(encoder.encode('reboot\n'), { timeout, signal });
        await reply;
      } finally { await this.close(); }
    });
    this._queue = task.catch(() => {}); return task;
  }
  async close() {
    this._ready = false; this._entered = false;
    if (this.waiter) { const waiter = this.waiter; this.waiter = null; waiter.reject(new Error('Serial connection closed')); }
    const link = this.link; this.link = null;
    if (link) { await link.close(); this.onState('disconnected'); }
  }
}
