import test from 'node:test';
import assert from 'node:assert/strict';
import { buildCommands, parseSettings, modeAfterSave } from '../src/config.js';
const board = { family: 'esp32', radio: 'SX1262' };
const radio = { role:'gateway', frequency:'915', bandwidth:'125', sf:'8', cr:'5', power:'0', airtime:'1' };
test('requires explicit frequency and power for an enabled radio', () => {
 assert.throws(() => buildCommands({...radio, frequency:''},board), /frequency/i);
 assert.throws(() => buildCommands({...radio, power:''},board), /power/i);
});
test('encodes MHz explicitly and saves only after validated commands', () => {
 const c=buildCommands(radio,board);
 assert.ok(c.includes('set lora.freq 915.000000'));
 assert.ok(c.includes('set lora.txp 0'));
 assert.equal(c.at(-1),'save');
 assert.ok(!c.includes('reboot'));
});
test('disabled LoRa does not invent RF settings', () => {
 assert.deepEqual(buildCommands({role:'off'},board),['set lora.mode off','save']);
});
test('rejects unsupported modem values and multiline command injection', () => {
 for(const override of [{sf:'4'},{cr:'9'},{bandwidth:'333'},{power:'23'},{frequency:'10000'}])
  assert.throws(()=>buildCommands({...radio,...override},board));
 assert.throws(()=>buildCommands({...radio,applyWifi:true,transport:'wifi',ssid:'net\nreboot',password:'12345678',host:'node',port:'4242'},board));
});
test('rejects Wi-Fi for nRF and allows valid host settings without storing them', () => {
 const wifi={role:'off',applyWifi:true,transport:'wifi',ssid:'network',password:'12345678',host:'relay.local',port:'4242'};
 assert.throws(()=>buildCommands(wifi,{family:'nrf52'}),/Wi-Fi/i);
 assert.ok(buildCommands(wifi,board).includes('set password 12345678'));
 assert.throws(()=>buildCommands({...wifi,host:'a'.repeat(64)},board),/host/i);
});
test('parses reported settings without treating masked password as the password', () => {
 const r=parseSettings('mode=wifi\r\nssid=net\r\npassword=(set)\r\nlora.freq=915000000\r\nlora.mode=gateway\r\nrnc> ');
 assert.equal(r['lora.freq'],'915000000');assert.equal(r.password,undefined);
});
test('changing Wi-Fi host preserves an existing password unless explicitly replaced', () => {
 const v={role:'off',applyWifi:true,transport:'wifi',ssid:'network',password:'',keepExistingPassword:true,host:'relay.local',port:'4242'};
 assert.ok(!buildCommands(v,board).some(c=>c.startsWith('set password')));
 assert.ok(buildCommands({...v,openNetwork:true},board).includes('set password '));
 assert.throws(()=>buildCommands({...v,keepExistingPassword:false},board),/password|open network/i);
});
test('rnode mode sends only the mode: the host sets the radio', () => {
 assert.deepEqual(buildCommands({runMode:'rnode'},board),['set mode rnode','save']);
 assert.deepEqual(buildCommands({runMode:'rnode',...radio,applyWifi:true,transport:'wifi'},board),['set mode rnode','save']);
 assert.throws(()=>buildCommands({runMode:'rnode'},{family:'esp32'}),/radio/i);
});
test('leaving rnode mode restores the serial node', () => {
 assert.deepEqual(buildCommands({runMode:'node',currentMode:'rnode',role:'off'},board),['set lora.mode off','set mode serial','save']);
 assert.ok(!buildCommands({runMode:'node',role:'off'},board).includes('set mode serial'));
 const wifi={role:'off',runMode:'node',currentMode:'rnode',applyWifi:true,transport:'serial'};
 assert.equal(buildCommands(wifi,board).filter(c=>c.startsWith('set mode')).length,1);
});
test('the reported rnode mode is parsed', () => {
 assert.equal(parseSettings('mode=rnode\r\nlora.mode=off\r\nrnc> ').mode,'rnode');
});
test('the mode after a save follows what was saved, so a second save in the same session is right', () => {
 assert.equal(modeAfterSave({runMode:'rnode'},'serial'),'rnode');
 assert.equal(modeAfterSave({runMode:'node'},'rnode'),'serial');
 assert.equal(modeAfterSave({runMode:'node',applyWifi:true,transport:'wifi'},'rnode'),'wifi');
 assert.equal(modeAfterSave({runMode:'node',applyWifi:true,transport:'serial'},'wifi'),'serial');
 assert.equal(modeAfterSave({runMode:'node'},'wifi'),'wifi');
 // rnode, save, back to node, save: the second save must send the mode back
 let mode=modeAfterSave({runMode:'rnode'},'serial');
 assert.ok(buildCommands({runMode:'node',role:'off',currentMode:mode},board).includes('set mode serial'));
});
