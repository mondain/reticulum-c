import { test, expect } from '@playwright/test';
async function serialMock(page){
 await page.addInitScript(()=>{
  window.sentCommands=[];window.delayClose=0;
  const port={
   async open(){this.readable=new ReadableStream({start:c=>this.controller=c});this.writable=new WritableStream({write:bytes=>{
    const c=new TextDecoder().decode(bytes).trim();window.sentCommands.push(c);
    const answer=c==='get'?'mode=serial\r\npassword=(set)\r\nlora.mode=gateway\r\nlora.freq=915000000\r\nlora.bw=125000\r\nlora.sf=8\r\nlora.cr=5\r\nlora.txp=0\r\nlora.airtime=1.00\r\n':c==='save'?'saving\r\nstored\r\n':c==='reboot'?'rebooting\r\n':'ok\r\n';
    this.controller.enqueue(new TextEncoder().encode(answer+(c==='reboot'?'':'rnc> ')));
   }});},async setSignals(){},async close(){await new Promise(r=>setTimeout(r,window.delayClose));this.readable=null;this.writable=null;},getInfo(){return{};}
  };
  Object.defineProperty(navigator,'serial',{value:{requestPort:async()=>port},configurable:true});
 });
}
const supreme=/LilyGo T-Beam Supreme SX1262, SX1262/;
test('exact board selection requires confirmation and offers UF2 fallback',async({page})=>{
 await serialMock(page);await page.goto('/');await expect(page.locator('.board-card')).toHaveCount(9);
 await page.getByRole('button',{name:supreme}).click();await expect(page.locator('#flash-button')).toBeDisabled();
 await page.locator('#confirm-board').check();await expect(page.locator('#flash-button')).toBeEnabled();
 await expect(page.getByRole('radio',{name:/Keep my identity/})).toBeChecked();
 await page.getByRole('button',{name:'nRF52840',exact:true}).click();await expect(page.locator('.board-card')).toHaveCount(3);
 await page.getByRole('button',{name:/LilyGo T-Echo, SX1262/}).click();await expect(page.locator('#nrf-help')).toBeVisible();
 await page.getByText('Downloads & checksums',{exact:true}).click();await expect(page.getByRole('link',{name:/UF2/})).toHaveAttribute('href',/reticulum-c-mcu.uf2$/);
});
test('download fallback works without Web Serial',async({page})=>{
 await page.addInitScript(()=>Object.defineProperty(navigator,'serial',{value:undefined,configurable:true}));await page.goto('/');
 await expect(page.locator('#browser-notice')).toBeVisible();await page.getByRole('button',{name:/LilyGo T-Echo, SX1262/}).click();await expect(page.locator('#flash-button')).toBeDisabled();
 await page.getByText('Downloads & checksums',{exact:true}).click();await expect(page.getByRole('link',{name:/UF2/})).toBeVisible();
});
test('reads settings before enabling commands, saves without implicit reboot',async({page})=>{
 await serialMock(page);await page.goto('/');await page.getByRole('button',{name:supreme}).click();await expect(page.locator('#save-settings')).toBeDisabled();
 await page.getByRole('button',{name:'Connect to settings',exact:true}).click();await expect(page.locator('#settings-state')).toHaveText('Setup console ready');
 await expect(page.getByLabel('Frequency (MHz)',{exact:true})).toHaveValue('915');await page.getByLabel('Frequency (MHz)',{exact:true}).fill('915.1');
 await page.locator('#save-settings').click();await expect(page.locator('#config-status')).toContainText('Settings saved');
 const commands=await page.evaluate(()=>window.sentCommands);expect(commands).toContain('set lora.freq 915.100000');expect(commands.at(-1)).toBe('save');expect(commands).not.toContain('reboot');
 await page.locator('#reboot').click();await expect(page.locator('#config-status')).toContainText('Reboot requested');
});
test('changing boards locks flashing while an old serial session closes',async({page})=>{
 await serialMock(page);await page.goto('/');await page.getByRole('button',{name:supreme}).click();await page.locator('#confirm-board').check();
 await page.locator('#connect-settings').click();await expect(page.locator('#settings-state')).toHaveText('Setup console ready');
 await page.evaluate(()=>window.delayClose=600);await page.getByRole('button',{name:/LilyGo T-Echo, SX1262/}).click();
 expect(await page.locator('#flash-button').isDisabled()).toBe(true);
});
test('mobile layout has no horizontal overflow',async({page},testInfo)=>{
 await page.setViewportSize({width:390,height:844});await page.goto('/');await expect(page.locator('.board-card')).toHaveCount(9);
 expect(await page.evaluate(()=>document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);await page.screenshot({path:testInfo.outputPath('mobile.png'),fullPage:true});
});

test('release change removes an unavailable board and closes its settings session',async({page,request})=>{
 const catalog=await (await request.get('/firmware/catalog.json')).json();
 catalog.releases.push({...catalog.releases[0],version:'another-build',boards:catalog.releases[0].boards.filter(b=>b.id==='lilygo_t_echo')});
 await page.route('**/firmware/catalog.json',r=>r.fulfill({json:catalog}));
 await serialMock(page);await page.goto('/');await page.getByRole('button',{name:supreme}).click();await page.locator('#connect-settings').click();
 await expect(page.locator('#settings-state')).toHaveText('Setup console ready');
 await page.locator('#version').selectOption('another-build');
 await expect(page.locator('#selected-description')).toHaveText('Select your board above to get started.');
 await expect(page.locator('#save-settings')).toBeDisabled();await expect(page.locator('#downloads .download-item')).toHaveCount(0);await expect(page.locator('#flash-button')).toBeDisabled();
});

test('Wi-Fi host changes do not clear a saved password implicitly',async({page})=>{
 await serialMock(page);await page.goto('/');await page.getByRole('button',{name:supreme}).click();await page.locator('#connect-settings').click();
 await expect(page.locator('#settings-state')).toHaveText('Setup console ready');await page.locator('#apply-wifi').check();await page.locator('#transport').selectOption('wifi');
 await page.locator('input[name="ssid"]').fill('network');await page.locator('input[name="host"]').fill('relay.local');await page.locator('input[name="port"]').fill('4242');
 await page.locator('#save-settings').click();await expect(page.locator('#config-status')).toContainText('Settings saved');
 expect((await page.evaluate(()=>window.sentCommands)).some(c=>c.startsWith('set password'))).toBe(false);
 await page.locator('#open-network').check();await page.locator('#save-settings').click();await expect(page.locator('#config-status')).toContainText('Settings saved');
 expect(await page.evaluate(()=>window.sentCommands)).toContain('set password');
});
