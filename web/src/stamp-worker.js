// One stamp search worker (see stamp.js): counts up from a random start in slices and reports its progress.
import { searchSlice } from './stamp.js';

function run(post, { material, cost, start, slice }) {
  const material90 = Uint8Array.from(material), counter = Uint8Array.from(start);
  let stopped = false;
  const step = () => {
    if (stopped) return;
    const found = searchSlice({ material: material90, cost, start: counter, attempts: slice });
    if (found) return post({ type: 'found', stamp: Array.from(found), tried: slice });
    post({ type: 'progress', tried: slice });
    // advance the start past this slice (the counter is big-endian over the 14 bytes)
    let carry = slice;
    for (let k = counter.length - 1; k >= 0 && carry; k--) { const v = counter[k] + (carry & 0xff); counter[k] = v & 0xff; carry = (carry >>> 8) + (v >> 8); }
    setTimeout(step, 0);
  };
  step();
  return () => { stopped = true; };
}
if (typeof self !== 'undefined' && typeof self.postMessage === 'function' && typeof window === 'undefined') {
  let stop = () => {};
  self.onmessage = event => { stop(); try { stop = run(m => self.postMessage(m), event.data); } catch (e) { self.postMessage({ type: 'error', message: e.message }); } };
}
export { run };
