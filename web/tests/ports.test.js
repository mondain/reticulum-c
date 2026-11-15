import test from 'node:test';
import assert from 'node:assert/strict';
import { waitForPort, deviceWarning } from '../src/ports.js';

const info = (usbVendorId, usbProductId) => ({ getInfo: () => ({ usbVendorId, usbProductId }) });

test('waitForPort finds the re-enumerated application port by USB ids', async () => {
  const app = info(0x239a, 0x8029), boot = info(0x239a, 0x0029);
  let calls = 0;
  const serial = { async getPorts() { return ++calls < 3 ? [boot] : [boot, app]; } };
  assert.equal(await waitForPort(serial, { usbVendorId: 0x239a, usbProductId: 0x8029 }, { timeout: 2000 }), app);
  assert.ok(calls >= 3);
});

test('waitForPort gives up, and does not poll without usable ids', async () => {
  const serial = { async getPorts() { return [info(1, 2)]; } };
  assert.equal(await waitForPort(serial, { usbVendorId: 9, usbProductId: 9 }, { timeout: 300 }), undefined);
  let polled = false;
  assert.equal(await waitForPort({ async getPorts() { polled = true; return []; } }, {}), undefined);
  assert.equal(polled, false);
});

test('deviceWarning flags non-Adafruit devices for nRF52 only', () => {
  const nrf = { family: 'nrf52' };
  assert.equal(deviceWarning(nrf, { usbVendorId: 0x239a }), '');
  assert.match(deviceWarning(nrf, { usbVendorId: 0x303a }), /not an Adafruit/);
  assert.equal(deviceWarning(nrf, {}), '');
  assert.equal(deviceWarning({ family: 'esp32' }, { usbVendorId: 0x303a }), '');
});
