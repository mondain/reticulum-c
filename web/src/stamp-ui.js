// The console side of stamping a board from the page: read the material, search, set, save.
import { findStamp, fromHex, hex, MATERIAL_SIZE, STAMP_SIZE } from './stamp.js';

export const STAMP_VALUE = 25; // what the firmware requires (RNC_MCU_STAMP_VALUE)

// The 90 byte material the board reports, as hex, or '' when it has no identity yet.
export async function readMaterial(session) {
  const reply = await session.command('get stamp.material');
  const m = /stamp\.material=([0-9a-fA-F]{180})\b/.exec(reply);
  return m ? m[1].toLowerCase() : '';
}
export async function setStamp({ session, hexText }) {
  const stamp = hex(fromHex(hexText, STAMP_SIZE)); // 28 digits or an error
  await session.command(`set stamp ${stamp}`);
  const saved = await session.command('save');
  if (!/stamp stored/i.test(saved)) throw new Error(`The board did not confirm storing the stamp: ${saved}`);
}
export async function stampBoard({ session, signal, makeWorker, workers, onProgress, cost = STAMP_VALUE }) {
  const material = await readMaterial(session);
  if (!material) throw new Error('The board has no identity yet. Start it once, then connect to settings again.');
  let tried = 0;
  const stamp = await findStamp({ material: fromHex(material, MATERIAL_SIZE), cost, workers, makeWorker, signal, onProgress: p => { tried = p.tried; onProgress?.(p); } });
  await setStamp({ session, hexText: hex(stamp) });
  return { stamp: hex(stamp), tried: tried || 0 };
}
