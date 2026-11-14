import SparkMD5 from 'spark-md5';
import { aborted, bounded, delay } from './serial.js';
import { readDfuPackage, flashApplication } from './nrf-dfu.js';

export { enterDfu } from './nrf-dfu.js';

export async function downloadVerified(file, baseUrl, { signal } = {}) {
  aborted(signal);
  if (!file || typeof file.path !== 'string' || !/^[A-Za-z0-9_./-]+$/.test(file.path) ||
      file.path.startsWith('/') || file.path.split('/').some(part => !part || part === '..' || part === '.'))
    throw new Error('Invalid firmware catalog path');
  if (!Number.isSafeInteger(file.size) || file.size < 1 || file.size > 32 * 1024 * 1024 || !/^[a-f0-9]{64}$/i.test(file.sha256))
    throw new Error('Firmware catalog must provide a valid byte size and SHA-256');
  const url = new URL(file.path, baseUrl);
  const response = await bounded(fetch(url, { signal, cache: 'no-cache' }), { timeout: 60000, signal, label: 'Firmware download' });
  if (!response.ok) throw new Error(`Firmware download failed: HTTP ${response.status}`);
  const bytes = new Uint8Array(await bounded(response.arrayBuffer(), { timeout: 60000, signal, label: 'Firmware download' }));
  if (bytes.length !== file.size) throw new Error(`Firmware size mismatch for ${file.path}`);
  const hash = [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map(b => b.toString(16).padStart(2, '0')).join('');
  if (hash !== file.sha256.toLowerCase()) throw new Error(`Firmware SHA-256 mismatch for ${file.path}`);
  aborted(signal); return bytes;
}

function binaryString(bytes) {
  let result = '';
  for (let offset = 0; offset < bytes.length; offset += 8192)
    result += String.fromCharCode(...bytes.subarray(offset, offset + 8192));
  return result;
}

export async function resetEspApplication(transport, { signal } = {}) {
  aborted(signal);
  // esptool-js 0.5.7 HardReset only releases RTS. Assert EN first, with IO0
  // released, so both USB/JTAG and external USB/UART adapters restart the app.
  await transport.setDTR(false);
  await transport.setRTS(true);
  try { await delay(100, signal); }
  finally { await transport.setRTS(false); }
}

export async function flashEsp({ port, board, baseUrl, onProgress = () => {}, onLog = () => {}, eraseAll = false, confirmErase = false, signal }) {
  if (board?.family !== 'esp32' || !['ESP32', 'ESP32-S3'].includes(board.chip) || !board.parts?.length)
    throw new Error('Choose a supported ESP32 firmware board');
  if (typeof eraseAll !== 'boolean') throw new Error('eraseAll must be an explicit boolean');
  if (eraseAll && confirmErase !== true) throw new Error('Factory erase requires explicit confirmation; identity and settings will be lost');
  const ranges = [];
  for (const part of board.parts) {
    if (!Number.isSafeInteger(part.offset) || part.offset < 0 || !Number.isSafeInteger(part.size) ||
        part.offset + part.size > 32 * 1024 * 1024) throw new Error('Invalid ESP flash offset or size');
    ranges.push([part.offset, part.offset + part.size]);
  }
  ranges.sort((a, b) => a[0] - b[0]);
  if (ranges.some((range, i) => i && range[0] < ranges[i - 1][1])) throw new Error('ESP flash parts overlap');
  onLog('Downloading and checking firmware SHA-256 before opening the device.'); onProgress(0);
  const files = await Promise.all(board.parts.map(async part => ({ data: binaryString(await downloadVerified(part, baseUrl, { signal })), address: part.offset })));
  aborted(signal);
  // Imported on demand so non-flashing pages and Node-based console tests do not
  // initialize the browser-dependent Espressif loader.
  const { ESPLoader, Transport } = await import('esptool-js');
  class CheckedTransport extends Transport {
    stopped = false;
    trace(message) { if (this.tracing) super.trace(message); }
    async connect(...args) { this.check(); return super.connect(...args); }
    check() { aborted(signal); if (this.stopped) throw new Error('ESP flashing connection closed'); }
    async write(data) {
      this.check();
      if (!this.device.writable) throw new Error('ESP serial port disconnected');
      const writer = this.device.writable.getWriter();
      try { await bounded(writer.write(this.slipWriter(data)), { timeout: 10000, signal, label: 'ESP serial write' }); }
      finally { writer.releaseLock(); }
    }
    async *read(timeout) { this.check(); yield* super.read(timeout); }
    async disconnect() {
      // v0.5.7 cancels its reader but never releases the lock before waiting for
      // it to unlock. Release explicitly for baud-rate changes and final cleanup.
      const reader = this.reader; this.reader = undefined;
      if (reader) {
        try { await reader.cancel(); } catch { /* Device may have disconnected. */ }
        try { reader.releaseLock(); } catch { /* An in-flight read may be ending. */ }
      }
      if (this.device.readable || this.device.writable) await this.device.close();
    }
  }
  const transport = new CheckedTransport(port, false);
  const terminal = { clean() {}, write: text => onLog(String(text)), writeLine: text => onLog(String(text)) };
  const loader = new ESPLoader({ transport, baudrate: 460800, romBaudrate: 115200, terminal });
  try {
    await bounded(loader.main(), { timeout: 90000, signal, label: 'ESP bootloader connection' });
    if (loader.chip?.CHIP_NAME !== board.chip)
      throw new Error(`Wrong chip: selected ${board.chip}, connected ${loader.chip?.CHIP_NAME ?? 'unknown'}. No firmware was written.`);
    onLog(`Verified connected chip: ${board.chip}. Writing firmware.`);
    if (eraseAll) onLog('Confirmed factory installation: erasing all flash, including identity and settings.');
    const completed = new Array(files.length).fill(0);
    const totalSize = files.reduce((sum, file) => sum + file.data.length, 0);
    await bounded(loader.writeFlash({
      fileArray: files, flashSize: 'keep', flashMode: 'keep', flashFreq: 'keep',
      eraseAll, compress: true,
      calculateMD5Hash: image => SparkMD5.hashBinary(image),
      reportProgress(index, written, total) {
        aborted(signal);
        completed[index] = files[index].data.length * (total ? written / total : 0);
        onProgress(Math.min(99, Math.floor(completed.reduce((sum, value) => sum + value, 0) / totalSize * 99)));
      },
    }), { timeout: 10 * 60 * 1000, signal, label: 'ESP firmware transfer' });
    aborted(signal);
    await bounded(resetEspApplication(transport, { signal }), { timeout: 5000, signal, label: 'ESP reset' });
    onProgress(100); onLog('ESP flash contents verified. Reconnect to configure the application.');
  } finally {
    transport.stopped = true;
    try { await bounded(transport.disconnect(), { timeout: 10000, label: 'ESP serial close' }); }
    catch (error) { onLog(`Serial cleanup: ${error.message}`); }
  }
}

export async function flashNrf({ port, board, baseUrl, onProgress = () => {}, onLog = () => {}, signal }) {
  if (board?.family !== 'nrf52' || board.chip !== 'nRF52840' || !board.files?.dfu)
    throw new Error('Choose a supported nRF52840 DFU firmware board');
  onLog('Downloading and checking application-only DFU package.'); onProgress(0);
  const zip = await downloadVerified(board.files.dfu, baseUrl, { signal });
  const image = await readDfuPackage(zip);
  aborted(signal);
  return flashApplication({ port, ...image, onProgress, onLog, signal });
}
