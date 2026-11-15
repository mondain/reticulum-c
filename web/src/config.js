const encoder = new TextEncoder();
function number(value, name, min, max, integer = false) {
 if (String(value ?? '').trim() === '') throw new Error(`Enter ${name}.`);
 const n = Number(value);
 if (!Number.isFinite(n) || n < min || n > max || (integer && !Number.isInteger(n)))
  throw new Error(`${name} must be ${integer ? 'an integer ' : ''}between ${min} and ${max}.`);
 return n;
}
function text(value, name, min, max) {
 const s = String(value ?? '');
 const size = encoder.encode(s).length;
 if (size < min || size > max || /[\x00-\x1f\x7f]/.test(s)) throw new Error(`Invalid ${name}.`);
 if (s.trim() !== s) throw new Error(`${name} cannot begin or end with whitespace.`);
 return s;
}
export function buildCommands(v, board) {
 if (v.runMode === 'rnode') {
  // an RNode modem: the host sets frequency, power and the rest; nothing radio-related is stored
  if (!board?.radio) throw new Error('RNode mode needs a board with a LoRa radio.');
  return ['set mode rnode', 'save'];
 }
 if (!['off','leaf','gateway'].includes(v.role)) throw new Error('Choose a radio mode.');
 const commands = [];
 if (v.role !== 'off') {
  const freq = number(v.frequency, 'frequency in MHz', 137, 1020);
  const bw = number(v.bandwidth, 'bandwidth', 7.8, 500);
  if (![7.8,10.4,15.6,20.8,31.25,41.7,62.5,125,250,500].includes(bw)) throw new Error('Unsupported bandwidth.');
  const sf = number(v.sf, 'spreading factor', board.radio === 'SX1276' ? 6 : 5, 12, true);
  const cr = number(v.cr, 'coding rate denominator', 5, 8, true);
  const power = number(v.power, 'transmit power in dBm', -9, board.radio === 'SX1276' ? 20 : 22, true);
  const airtime = number(v.airtime, 'airtime percent', 0.01, 100);
  commands.push(`set lora.freq ${freq.toFixed(6)}`, `set lora.bw ${bw}`, `set lora.sf ${sf}`,
   `set lora.cr ${cr}`, `set lora.txp ${power}`, `set lora.airtime ${airtime.toFixed(2)}`);
 }
 commands.push(`set lora.mode ${v.role}`);
 if (v.applyWifi) {
  if (board.family !== 'esp32') throw new Error('Wi-Fi is unavailable on this board.');
  if (!['serial','wifi'].includes(v.transport)) throw new Error('Choose a host connection.');
  if (v.transport === 'wifi') {
   if (v.role === 'leaf') throw new Error('Wi-Fi requires radio off or gateway mode.');
   const ssid=text(v.ssid,'Wi-Fi network',1,32), password=text(v.password,'Wi-Fi password',0,63);
   if (password.length && encoder.encode(password).length < 8) throw new Error('Wi-Fi password needs 8–63 bytes, or leave it empty for an open network.');
   const host=text(v.host,'host',1,63);
   if (/[^\x21-\x7e]/.test(host)) throw new Error('Invalid host.');
   const port=number(v.port,'TCP port',1,65535,true);
   if (!password && !v.openNetwork && !v.keepExistingPassword) throw new Error('Enter a Wi-Fi password or explicitly choose an open network.');
   if (v.openNetwork && password) throw new Error('Clear the password before choosing an open network.');
   commands.push(`set ssid ${ssid}`);
   if (password || v.openNetwork) commands.push(`set password ${password}`);
   commands.push(`set host ${host}`, `set port ${port}`);
  }
  commands.push(`set mode ${v.transport}`);
 }
 if (v.currentMode === 'rnode' && !v.applyWifi) commands.push('set mode serial'); // leaving RNode mode
 commands.push('save');
 return commands;
}
export function parseSettings(reply) {
 const values = {};
 for (const line of reply.split(/\r?\n/)) {
  const m=line.match(/^([a-z.]+)=(.*)$/);
  if (m && m[1] !== 'password') values[m[1]]=m[2];
 }
 return values;
}
