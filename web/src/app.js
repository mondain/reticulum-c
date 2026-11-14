import './style.css';
import { flashEsp, flashNrf, enterDfu } from './flash.js';
import { ConsoleSession } from './serial.js';
import { buildCommands, parseSettings } from './config.js';
const $=id=>document.getElementById(id), catalogueUrl=new URL('./firmware/catalog.json',document.baseURI);
let catalogue,release,selected,filter='all',busy=false,settings,applicationPort,currentPasswordSet=false;
const webSerial=!!navigator.serial&&window.isSecureContext;
$('browser-notice').hidden=webSerial;
function status(text,kind=''){ $('status').textContent=text;$('status').className=`status ${kind}`; }
function configStatus(text,kind=''){ $('config-status').textContent=text;$('config-status').className=`status ${kind}`; }
function log(line){ $('log').textContent=($('log').textContent+String(line).replace(/(set password\s+)[^\r\n]*/gi,'$1[hidden]')+'\n').slice(-18000);$('log').scrollTop=$('log').scrollHeight; }
const artwork='<svg class="board-visual" viewBox="0 0 85 60" aria-hidden="true"><rect class="pcb" x="12" y="7" width="61" height="45" rx="5"/><rect class="chip" x="33" y="19" width="21" height="21" rx="2"/><rect class="chip" x="8" y="21" width="10" height="16" rx="2"/><path d="M24 12v7m0 23v6m37-36v7m0 23v6M22 26h7m27 0h10M22 34h7m27 0h10M73 15h7v10h-4v10h4v10h-7"/><circle cx="20" cy="14" r="2" fill="#d8ed9c"/><circle cx="65" cy="45" r="2" fill="#d8ed9c"/></svg>';
function syncActions(){
 const enabled=!!selected&&webSerial&&!busy;
 $('flash-button').disabled=!enabled||!$('confirm-board').checked;
 $('connect-settings').disabled=!enabled;$('enter-dfu').disabled=!enabled;
 $('version').disabled=busy||!catalogue?.releases?.length;
 document.querySelectorAll('.board-card,.filter').forEach(b=>b.disabled=busy);
 $('install-mode').disabled=busy;$('confirm-board').disabled=busy;$('config-fields').disabled=busy||!settings?.inConsole;
}
function drawBoards(){
 const grid=$('board-grid');grid.replaceChildren();
 const boards=[...(release?.boards||[])].sort((a,b)=>Number(b.hardwareTested)-Number(a.hardwareTested));
 for(const b of boards.filter(b=>filter==='all'||b.family===filter)){
  const button=document.createElement('button');button.type='button';button.className=`board-card${selected?.id===b.id?' selected':''}`;
  button.setAttribute('aria-pressed',String(selected?.id===b.id));button.setAttribute('aria-label',`${b.name}, ${b.radio}, ${b.hardwareTested?'bench tested':'build tested'}`);button.innerHTML=artwork;
  const badge=document.createElement('span');badge.className=`tested${b.hardwareTested?'':' build-only'}`;badge.textContent=b.hardwareTested?'BENCH TESTED':'BUILD TESTED';button.append(badge);
  for(const [tag,cl,txt]of[['span','board-family',b.chip],['strong','',b.name],['span','radio-name',b.radio]]){const e=document.createElement(tag);e.className=cl;e.textContent=txt;button.append(e);}
  button.addEventListener('click',()=>choose(b));grid.append(button);
 }syncActions();
}
async function choose(board){
 if(busy)return;
 busy=true;selected=undefined;$('confirm-board').checked=false;syncActions();
 try {
  if(settings){await settings.close();settings=undefined;}
  selected=board;applicationPort=undefined;currentPasswordSet=false;$('config-form').reset();$('settings-state').textContent='No settings session';
  $('connection-badge').textContent='Not connected';$('connection-badge').classList.remove('connected');
  $('selected-description').textContent=`${board.name} · ${board.radio} · ${board.chip}`;
  $('nrf-help').hidden=board.family!=='nrf52';$('install-mode').hidden=board.family==='nrf52';$('wifi-section').hidden=board.family!=='esp32';
  configStatus('Settings are only sent after a setup prompt is detected.');updateFields();drawBoards();drawDownloads();
  status(webSerial?'Ready. Confirm the board model, then connect your USB device.':'Downloads are available; this browser does not support Web Serial.');
 }catch(e){status(e.message,'error');}finally{busy=false;syncActions();}
}
function drawDownloads(){
 const target=$('downloads');target.replaceChildren();if(!selected)return;
 const assets=selected.family==='nrf52'?Object.entries(selected.files):selected.parts.map((v,i)=>[i===0?'Bootloader':v.offset===65536?'Application':`Flash part at 0x${v.offset.toString(16)}`,v]);
 for(const[role,file]of assets){const box=document.createElement('div');box.className='download-item';const a=document.createElement('a');a.href=new URL(file.path,catalogueUrl).href;a.download='';a.textContent=`${role.toUpperCase()} · ${(file.size/1024).toFixed(1)} KB`;box.append(a);const hash=document.createElement('small');hash.textContent=`SHA-256 ${file.sha256}`;box.append(hash);target.append(box);}
}
function updateFields(){ $('config-form').elements.namedItem('password').disabled=$('open-network').checked;$('radio-fields').hidden=$('radio-role').value==='off';$('wifi-fields').hidden=!$('apply-wifi').checked;$('wifi-values').hidden=$('transport').value!=='wifi'; }
function loadReportedSettings(reply){
 const v=parseSettings(reply),f=$('config-form').elements;currentPasswordSet=/(?:^|\r?\n)password=\(set\)/.test(reply);
 for(const[key,name]of[['lora.mode','role'],['lora.sf','sf'],['lora.cr','cr'],['lora.txp','power'],['lora.airtime','airtime'],['mode','transport'],['ssid','ssid'],['host','host'],['port','port']])if(v[key]!==undefined&&v[key]!=='(not set)')f.namedItem(name).value=v[key];
 if(v['lora.freq']&&v['lora.freq']!=='(not set)')f.namedItem('frequency').value=Number(v['lora.freq'])/1e6;
 if(v['lora.bw']&&v['lora.bw']!=='(not set)')f.namedItem('bandwidth').value=Number(v['lora.bw'])/1000;
 f.namedItem('password').value='';updateFields();
}
async function openSettings(port,freshBoot=false){
 if(settings)await settings.close();
 settings=new ConsoleSession({onLog:log,onState:s=>{$('settings-state').textContent=s==='console'?'Setup console ready':s==='connected'?'Waiting for setup prompt':'Disconnected';$('connection-badge').textContent=s==='console'?'Settings connected':'Not connected';$('connection-badge').classList.toggle('connected',s==='console');syncActions();}});
 if(freshBoot){let last;for(let i=0;i<35;i++){try{await settings.connect(port);last=undefined;break;}catch(e){last=e;await new Promise(r=>setTimeout(r,120));}}if(last)throw last;}
 else await settings.connect(port);
 configStatus(freshBoot?'Entering setup after installation…':'Tap RESET now. Waiting for the board’s setup prompt…');
 await settings.enterConsole({timeout:15000});loadReportedSettings(await settings.command('get'));
 configStatus('Saved settings loaded. Change the fields, save, then reboot to run.','success');
}
$('open-network').addEventListener('change',()=>{const p=$('config-form').elements.namedItem('password');p.disabled=$('open-network').checked;if(p.disabled)p.value='';});
$('confirm-board').addEventListener('change',syncActions);$('clear-log').addEventListener('click',()=>$('log').textContent='');
for(const id of['radio-role','apply-wifi','transport'])$(id).addEventListener('change',updateFields);
document.querySelectorAll('.filter').forEach(b=>b.addEventListener('click',()=>{filter=b.dataset.family;document.querySelectorAll('.filter').forEach(x=>{x.classList.toggle('active',x===b);x.setAttribute('aria-pressed',String(x===b));});drawBoards();}));
$('version').addEventListener('change',async()=>{
 if(busy)return;
 const id=selected?.id,version=$('version').value;busy=true;selected=undefined;$('confirm-board').checked=false;syncActions();
 try {
  if(settings){await settings.close();settings=undefined;}
  release=catalogue.releases.find(r=>r.version===version);applicationPort=undefined;
  $('selected-description').textContent='Select your board above to get started.';$('downloads').replaceChildren();
  $('settings-state').textContent='No settings session';$('connection-badge').textContent='Not connected';$('connection-badge').classList.remove('connected');
  $('config-form').reset();updateFields();$('nrf-help').hidden=true;
  $('release-meta').textContent=`Source ${release.commit.slice(0,12)}${release.development?' · development build':''}`;drawBoards();
 }catch(e){status(e.message,'error');}finally{busy=false;syncActions();}
 const next=release?.boards.find(b=>b.id===id);if(next)await choose(next);
});
$('enter-dfu').addEventListener('click',async()=>{
 busy=true;syncActions();try{if(settings){await settings.close();settings=undefined;}applicationPort=await navigator.serial.requestPort();await enterDfu(applicationPort,{onLog:log});status('Bootloader requested. Click Connect & install, then choose the bootloader port.');}
 catch(e){status(e.message||String(e),'error');log(e.message||e);}finally{busy=false;syncActions();}
});
$('flash-button').addEventListener('click',async()=>{
 if(!selected||busy)return;
 const board=selected;
 const eraseAll=board.family==='esp32'&&document.querySelector('input[name="install-mode"]:checked').value==='factory';
 if(eraseAll&&!window.confirm('Erase the entire ESP32 flash? The existing identity and saved settings will be lost.'))return;
 busy=true;syncActions();$('progress-wrap').hidden=false;$('progress').value=0;
 try{
  if(settings){await settings.close();settings=undefined;}
  const port=await navigator.serial.requestPort();const options={port,board,baseUrl:catalogueUrl,onLog:log,onProgress:n=>{$('progress').value=n;$('progress-text').textContent=`${Math.floor(n)}%`;}};
  status('Verifying firmware and connecting to the bootloader. Keep USB connected.');
  if(board.family==='esp32')await flashEsp({...options,eraseAll,confirmErase:eraseAll});else await flashNrf(options);
  status('Firmware transfer verified. The board is rebooting.','success');
  const appPort=board.family==='esp32'?port:applicationPort;
  if(appPort){try{await openSettings(appPort,true);status('Installation complete. Configure your node below.','success');$('configure').scrollIntoView({behavior:'smooth'});}catch(e){log(`Setup connection: ${e.message}`);configStatus('Firmware installed. Use Connect to settings and RESET if automatic setup could not connect.');}}
  else configStatus('Firmware installed. Select the application USB port using Connect to settings.');
 }catch(e){status(`Installation stopped: ${e.message||String(e)}. Re-enter the bootloader to retry.`,'error');log(e.message||e);}finally{busy=false;syncActions();}
});
$('connect-settings').addEventListener('click',async()=>{
 busy=true;syncActions();try{applicationPort=await navigator.serial.requestPort();await openSettings(applicationPort);}
 catch(e){configStatus(`${e.message||String(e)}. Select the application port and retry after RESET.`,'error');log(e.message||e);if(settings)await settings.close();}finally{busy=false;syncActions();}
});
$('config-form').addEventListener('submit',async event=>{
 event.preventDefault();if(!settings?.inConsole||busy)return;
 try{const f=new FormData(event.currentTarget),values=Object.fromEntries(f);values.applyWifi=f.has('applyWifi');values.openNetwork=f.has('openNetwork');values.keepExistingPassword=currentPasswordSet;const commands=buildCommands(values,selected);busy=true;syncActions();configStatus('Writing validated settings…');for(const c of commands)await settings.command(c);if(values.applyWifi&&values.transport==='wifi')currentPasswordSet=!!values.password||(!values.openNetwork&&currentPasswordSet);$('config-form').elements.namedItem('password').value='';configStatus('Settings saved. Press Reboot & run to apply them.','success');}
 catch(e){configStatus(`Settings were not confirmed saved: ${e.message||String(e)}. Read them again before retrying.`,'error');log(e.message||e);}finally{busy=false;syncActions();}
});
$('reboot').addEventListener('click',async()=>{
 if(!settings?.inConsole||busy)return;busy=true;syncActions();try{await settings.reboot();settings=undefined;configStatus('Reboot requested. The board is starting with the saved settings.','success');}catch(e){configStatus(e.message,'error');}finally{busy=false;syncActions();}
});
async function start(){
 try{
  const response=await fetch(catalogueUrl,{cache:'no-store'});if(!response.ok)throw new Error(`Catalogue HTTP ${response.status}`);catalogue=await response.json();if(catalogue.schema!==1||!catalogue.releases?.length)throw new Error('No published firmware releases are available.');
  $('version').replaceChildren();for(const r of catalogue.releases){const option=document.createElement('option');option.value=r.version;option.textContent=`${r.version.startsWith('main-')?'Preview · ':''}${r.version}`;$('version').append(option);}release=catalogue.releases[0];$('release-meta').textContent=`Source ${release.commit.slice(0,12)}${release.development?' · development build':''}`;drawBoards();status(webSerial?'Choose your exact board to begin.':'Choose a board to download its firmware.');
 }catch(e){$('board-grid').textContent='Firmware is not available yet. Please check the project releases or try again shortly.';status(e.message,'error');log(e.message);}syncActions();
}
void start();
