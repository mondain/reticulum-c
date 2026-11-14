import { ConsoleSession, aborted, delay } from './serial.js';
import { waitForPort } from './ports.js';

// Opens the provisioning console and keeps trying until `timeout` ms have passed.
// Boards with native USB (nRF52840, ESP32-S3) drop off the bus when they reset, which
// is exactly what the user does to open the short window in which the firmware accepts
// "rnc-config". The dead port is closed, the board is looked up again by its USB ids,
// and entry is retried on the new connection. Returns the session, ready for commands.
export async function connectConsole({
  serial, port, signal, timeout = 30000, reconnectWait = 5000,
  makeSession = options => new ConsoleSession(options),
  sessionOptions = {}, onSession = () => {}, onLog = () => {},
}) {
  const info = port.getInfo?.();
  const deadline = Date.now() + timeout;
  for (;;) {
    aborted(signal);
    const session = makeSession({ ...sessionOptions, onLog });
    onSession(session);
    try {
      await session.connect(port);
      await session.enterConsole({ signal, timeout: Math.max(1000, deadline - Date.now()) });
      return session;
    } catch (error) {
      await session.close().catch(() => {});
      aborted(signal);
      if (Date.now() >= deadline) throw error;
      onLog(`Serial connection lost (${error.message}); waiting for the board to reappear.`);
      port = (await waitForPort(serial, info, { timeout: Math.min(reconnectWait, Math.max(0, deadline - Date.now())), signal })) || port;
      await delay(150, signal);
    }
  }
}
