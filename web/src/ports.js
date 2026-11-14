import { delay } from './serial.js';

const ADAFRUIT_VENDOR = 0x239a;

function sameDevice(info, wanted) {
  return info?.usbVendorId === wanted.usbVendorId && info?.usbProductId === wanted.usbProductId;
}

// USB devices re-enumerate after a reset or a DFU run, and Chrome may hand out a new
// SerialPort object (or none) for them. Look the granted ports up again by USB ids.
// `wanted` is the getInfo() of the application port, read before flashing.
export async function waitForPort(serial, wanted, { timeout = 10000, signal } = {}) {
  if (!serial?.getPorts || wanted?.usbVendorId === undefined || wanted?.usbProductId === undefined) return undefined;
  const started = Date.now();
  do {
    const found = (await serial.getPorts()).find(port => sameDevice(port.getInfo?.(), wanted));
    if (found) return found;
    await delay(250, signal);
  } while (Date.now() - started < timeout);
  return undefined;
}

// Returns a warning for a port that does not look like the selected board's family.
// USB ids cannot tell the three nRF52840 boards apart (they share the Adafruit
// bootloader ids), so this catches picking the wrong device, not the wrong board.
export function deviceWarning(board, info) {
  if (board?.family !== 'nrf52' || info?.usbVendorId === undefined) return '';
  return info.usbVendorId === ADAFRUIT_VENDOR ? '' :
    `The selected USB device (vendor 0x${info.usbVendorId.toString(16)}) is not an Adafruit-bootloader nRF52840 board.`;
}
