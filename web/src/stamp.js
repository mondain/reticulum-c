// RNS 1.6 network stamps in the browser: the cost arithmetic of src/netstamp.c, a SHA-256 that hashes
// only the last block per trial, and a search that runs in workers. A destination stamp is 14 bytes
// that, appended to the board's 90 byte material, make SHA-256 land under a target set by the cost.
import { TAB } from './stamp-table.js';

export const STAMP_SIZE = 14;
export const MATERIAL_SIZE = 90;
export const COST_CAP = 100;

export function costToFp(cost) {
  if (!(cost > 0)) return 0;
  const v = Math.floor(cost * 256 + 0.5);
  return v >= COST_CAP * 256 ? COST_CAP * 256 : v;
}
// target_from_fp: (TAB[f] << i) >> 33 with i, f = divmod(256 * 256 - fp, 256); at 2^256 or more everything passes.
export function targetFromFp(fp) {
  const i = Math.floor((65536 - fp) / 256), f = (65536 - fp) % 256;
  const target = (TAB[f] << BigInt(i)) >> 33n;
  return target >= 1n << 256n ? (1n << 256n) - 1n : target;
}
export const targetFromCost = cost => targetFromFp(costToFp(cost));

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
  0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
  0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
const H0 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
const W = new Uint32Array(64);
// One compression of the 64 byte block held in w[0..15] into state h.
function compress(h, w) {
  for (let t = 0; t < 16; t++) W[t] = w[t];
  for (let t = 16; t < 64; t++) {
    const a = W[t - 15], b = W[t - 2];
    const s0 = ((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3);
    const s1 = ((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10);
    W[t] = (W[t - 16] + s0 + W[t - 7] + s1) | 0;
  }
  let a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
  for (let t = 0; t < 64; t++) {
    const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
    const ch = (e & f) ^ (~e & g);
    const t1 = (hh + S1 + ch + K[t] + W[t]) | 0;
    const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
    const maj = (a & b) ^ (a & c) ^ (b & c);
    const t2 = (S0 + maj) | 0;
    hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
  }
  h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0;
  h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + g) | 0; h[7] = (h[7] + hh) | 0;
}
function words(block) {
  const w = new Uint32Array(16);
  for (let i = 0; i < 16; i++) w[i] = (block[4 * i] << 24) | (block[4 * i + 1] << 16) | (block[4 * i + 2] << 8) | block[4 * i + 3];
  return w;
}
export function sha256(bytes) {
  const h = Int32Array.from(H0), padded = Math.ceil((bytes.length + 9) / 64) * 64;
  const data = new Uint8Array(padded);
  data.set(bytes);
  data[bytes.length] = 0x80;
  const bits = BigInt(bytes.length) * 8n;
  for (let i = 0; i < 8; i++) data[padded - 1 - i] = Number((bits >> BigInt(8 * i)) & 0xffn);
  for (let off = 0; off < padded; off += 64) compress(h, words(data.subarray(off, off + 64)));
  const out = new Uint8Array(32);
  for (let i = 0; i < 8; i++) { out[4 * i] = h[i] >>> 24; out[4 * i + 1] = (h[i] >>> 16) & 255; out[4 * i + 2] = (h[i] >>> 8) & 255; out[4 * i + 3] = h[i] & 255; }
  return out;
}
const toBig = bytes => BigInt('0x' + [...bytes].map(b => b.toString(16).padStart(2, '0')).join(''));
export const hex = bytes => [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
export function fromHex(text, size) {
  if (typeof text !== 'string' || text.length !== 2 * size || !/^[0-9a-fA-F]+$/.test(text)) throw new Error(`Expected ${2 * size} hexadecimal digits`);
  return Uint8Array.from(text.match(/../g), p => parseInt(p, 16));
}
export function stampValid(material, stamp, cost) {
  const joined = new Uint8Array(material.length + stamp.length);
  joined.set(material); joined.set(stamp, material.length);
  return toBig(sha256(joined)) <= targetFromCost(cost);
}

// The search core. For a 90 byte material and a 14 byte stamp the message is 104 bytes: two blocks, the first
// (material[0..64]) is compressed once, so a trial is a single compression of material[64..90] + stamp + padding.
// Returns the stamp that meets `cost`, or null after `attempts` trials. `random` fills the starting point.
export function searchSlice({ material, cost, start, attempts }) {
  if (material.length !== MATERIAL_SIZE) throw new Error('The stamp material is 90 bytes');
  const target = targetFromCost(cost);
  const state = Int32Array.from(H0);
  compress(state, words(material.subarray(0, 64)));
  const tail = 90 - 64; // 26 bytes of material in the second block
  const block = new Uint8Array(64);
  block.set(material.subarray(64));
  block[tail + STAMP_SIZE] = 0x80;
  const bits = (MATERIAL_SIZE + STAMP_SIZE) * 8; // 832
  block[62] = bits >> 8; block[63] = bits & 255;
  const counter = Uint8Array.from(start);
  const h = new Int32Array(8), w = new Uint32Array(16), digest = new Uint8Array(32);
  for (let n = 0; n < attempts; n++) {
    block.set(counter, tail);
    for (let i = 0; i < 16; i++) w[i] = (block[4 * i] << 24) | (block[4 * i + 1] << 16) | (block[4 * i + 2] << 8) | block[4 * i + 3];
    h.set(state);
    compress(h, w);
    // cheap rejection: a target below 2^224 needs the first word to be zero
    if (target >= 1n << 224n || h[0] === 0) {
      for (let i = 0; i < 8; i++) { digest[4 * i] = h[i] >>> 24; digest[4 * i + 1] = (h[i] >>> 16) & 255; digest[4 * i + 2] = (h[i] >>> 8) & 255; digest[4 * i + 3] = h[i] & 255; }
      if (toBig(digest) <= target) return Uint8Array.from(counter);
    }
    for (let k = STAMP_SIZE - 1; k >= 0; k--) { counter[k] = (counter[k] + 1) & 255; if (counter[k] !== 0) break; }
  }
  return null;
}

// Searches with `workers` parallel workers. `makeWorker()` returns an object with postMessage / onmessage /
// terminate (a DOM Worker, or an adapter in tests). Resolves with the stamp; rejects with an AbortError when
// `signal` aborts. onProgress({ tried, seconds }) is called as work completes.
export function findStamp({ material, cost, workers = 4, makeWorker, onProgress = () => {}, signal, slice = 1 << 16 }) {
  return new Promise((resolve, reject) => {
    const started = Date.now(), pool = [];
    let tried = 0, done = false;
    const stop = () => { for (const w of pool) { try { w.terminate(); } catch { /* gone */ } } pool.length = 0; };
    const finish = (fn, value) => { if (done) return; done = true; stop(); signal?.removeEventListener('abort', onAbort); fn(value); };
    const onAbort = () => finish(reject, Object.assign(new Error('Stamp search cancelled'), { name: 'AbortError' }));
    if (signal?.aborted) return onAbort();
    signal?.addEventListener('abort', onAbort);
    for (let i = 0; i < Math.max(1, workers); i++) {
      const worker = makeWorker();
      worker.onmessage = event => {
        if (done) return; // a late message from a worker that was already stopped
        const m = event.data;
        if (m.type === 'progress') { tried += m.tried; onProgress({ tried, seconds: (Date.now() - started) / 1000 }); }
        else if (m.type === 'found') { tried += m.tried; finish(resolve, Uint8Array.from(m.stamp)); }
        else if (m.type === 'error') finish(reject, new Error(m.message));
      };
      worker.onerror = error => finish(reject, new Error(error.message || 'Stamp worker failed'));
      const start = crypto.getRandomValues(new Uint8Array(STAMP_SIZE));
      worker.postMessage({ material: Array.from(material), cost, start: Array.from(start), slice });
      pool.push(worker);
    }
  });
}
