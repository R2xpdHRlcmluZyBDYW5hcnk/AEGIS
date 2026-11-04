import {testOutput} from './test-output.mjs';
// Dependency-free Chrome DevTools smoke test. Start serve_preview.py first.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, writeFile, mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
const profile = await mkdtemp(path.join(tmpdir(), 'ndr-chrome-'));
const chromePath = process.env.CHROME_PATH || 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const chrome = spawn(chromePath, ['--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check', '--remote-debugging-port=0', '--remote-allow-origins=*', `--user-data-dir=${profile}`, 'about:blank'], { windowsHide: true, stdio: 'ignore' });
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
let ws;
try {
  let port;
  for (let i = 0; i < 100; i++) {
    try { port = Number((await readFile(path.join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')[0]); break; }
    catch { await pause(100); }
  }
  assert.ok(port, 'Chrome starts');
  const tab = await (await fetch(`http://127.0.0.1:${port}/json/new?about:blank`, { method: 'PUT' })).json();
  ws = new WebSocket(tab.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; });
  const pending = new Map(), exceptions = [];
  let id = 0;
  ws.onmessage = ({ data }) => {
    const message = JSON.parse(data);
    if (message.method === 'Runtime.exceptionThrown') exceptions.push(message.params.exceptionDetails);
    if (message.id && pending.has(message.id)) {
      const { resolve, reject } = pending.get(message.id); pending.delete(message.id);
      message.error ? reject(new Error(JSON.stringify(message.error))) : resolve(message.result);
    }
  };
  function cdp(method, params = {}) {
    const sequence = ++id;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { pending.delete(sequence); reject(new Error('CDP timeout: ' + method)); }, 15000);
      pending.set(sequence, { resolve: value => { clearTimeout(timer); resolve(value); }, reject: error => { clearTimeout(timer); reject(error); } });
      ws.send(JSON.stringify({ id: sequence, method, params }));
    });
  }
  async function evaluate(expression) {
    const result = await cdp('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
    if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
    return result.result.value;
  }
  async function execute(script) { return evaluate('(async () => {' + script + '\n})()'); }
  async function until(expression) {
    for (let i = 0; i < 100; i++) {
      if (await evaluate(expression)) return;
      await pause(100);
    }
    throw new Error('Condition timed out: ' + expression + '\nBrowser exceptions: ' +
      JSON.stringify(exceptions) + '\nPage: ' + await evaluate('document.body.innerText.slice(-4500)'));
  }
  await cdp('Runtime.enable');await cdp('Page.enable');
  await cdp('Page.addScriptToEvaluateOnNewDocument',{source:`window.testStreams=[];window.EventSource=class{static OPEN=1;readyState=1;constructor(url){this.url=url;window.testStreams.push(this)}close(){this.readyState=2}}`});
  await cdp('Emulation.setDeviceMetricsOverride',{width:1440,height:1100,deviceScaleFactor:1,mobile:false});
  await cdp('Page.navigate',{url:'http://127.0.0.1:19091/login'});await until(`!!document.querySelector('#password')`);
  await evaluate(`document.querySelector('#password').value='preview-only';document.querySelector('form').submit()`);await until(`!!document.querySelector('ndr-chart')`);
  async function pointerClick(selector){
    await pause(350);const point=await evaluate(`(()=>{const e=document.querySelector(${JSON.stringify(selector)});if(!e)throw new Error('Missing '+${JSON.stringify(selector)});e.scrollIntoView({block:'center',inline:'center'});const r=e.getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2}})()`);
    await cdp('Input.dispatchMouseEvent',{type:'mouseMoved',...point});
    await cdp('Input.dispatchMouseEvent',{type:'mousePressed',...point,button:'left',clickCount:1});
    await cdp('Input.dispatchMouseEvent',{type:'mouseReleased',...point,button:'left',clickCount:1});
  }

  const overview=await execute(`return await (await fetch('/api/overview?window=60')).json()`);
  for(let repeat=0;repeat<3;repeat++){
    await evaluate(`window.testStreams.at(-1).onmessage({data:JSON.stringify({...${JSON.stringify(overview)},top:{signatures:[{sig:'engine drop: flow drop',sid:null,sev:0,count:1}]}})})`);
    await until(`document.querySelector('ndr-overview .three-grid ndr-table')?.textContent.includes('engine drop: flow drop')`);
    await pointerClick('ndr-overview .three-grid ndr-table tbody tr');
    await until(`document.querySelector('ndr-hunt-query input')?.value==='type:drop sig:"engine drop: flow drop"'`);
    await until(`!document.querySelector('ndr-events .page-loading')`);await pause(250);
    assert.equal(await evaluate(`document.querySelector('ndr-events .error')?.textContent||''`),'');
    await pointerClick('[data-page="overview"]');await until(`!!document.querySelector('ndr-chart')`);
    assert.equal(await evaluate(`document.body.innerText.includes('undefined')`),false);
  }
  console.log('ok - engine drop without SID generates a valid drop/signature query; repeated return to overview has no runtime errors');
  await pointerClick('[data-page="system"]');await until(`!!document.querySelector('#db-capacity')&&!!document.querySelector('.system-grid dd')`);
  const api=script=>execute(`const r=await fetch('/api/db/settings',{method:'POST',headers:{'Content-Type':'application/json','X-Requested-With':'ips-web'},body:JSON.stringify(${script})});return {status:r.status,body:await r.json()}`);
  assert.equal((await api('{cap_mib:63}')).status,400);
  assert.equal((await api('{cap_mib:"512"}')).status,400);
  const original=await evaluate(`document.querySelector('#db-capacity').value`);
  async function input(value){await evaluate(`(()=>{const e=document.querySelector('#db-capacity');e.value=${JSON.stringify(value)};e.dispatchEvent(new Event('input',{bubbles:true}))})()`);}
  async function unit(value){await evaluate(`(()=>{const e=document.querySelector('[name="capacity-unit"]');e.value=${JSON.stringify(value)};e.dispatchEvent(new Event('change',{bubbles:true}))})()`);}
  assert.equal(await evaluate(`document.querySelector('[name="capacity-unit"]').value`),'GiB');
  await input('1.5');await unit('MiB');assert.equal(await evaluate(`document.querySelector('#db-capacity').value`),'1536');
  await unit('GiB');assert.equal(await evaluate(`document.querySelector('#db-capacity').value`),'1.5');
  await pointerClick('.db-capacity button');await until(`document.querySelector('.db-capacity button').disabled&&document.querySelector('.db-capacity button').textContent==='保存'`);
  assert.equal(await execute(`return (await (await fetch('/api/db/stats')).json()).cap`),1610612736);
  await pointerClick('[data-page="overview"]');await until(`!!document.querySelector('ndr-chart')`);
  await pointerClick('[data-page="system"]');await until(`document.querySelector('#db-capacity')?.value==='1.5'`);
  await evaluate(`document.querySelector('.database-card').scrollIntoView()`);
  assert.ok(await evaluate(`document.querySelector('.db-capacity label').getBoundingClientRect().left-document.querySelector('.database-card').getBoundingClientRect().left>=16`));
  await input('0.0626');await pointerClick('.db-capacity button');await until(`document.querySelector('.database-card .error')?.textContent.includes('整数 MiB')`);
  assert.equal(await execute(`return (await (await fetch('/api/db/stats')).json()).cap`),1610612736);
  await input(original);await pointerClick('.db-capacity button');await until(`document.querySelector('.db-capacity button').disabled&&document.querySelector('.db-capacity button').textContent==='保存'`);
  // Real triple click selects status text; data and DOM must stay stable until selection clears.
  await evaluate(`window.selectedNode=document.querySelector('.system-grid dd');window.originalSection=selectedNode.closest('section');window.statusText=selectedNode.textContent;selectedNode.scrollIntoView({block:'center'})`);
  const point=await evaluate(`(()=>{const r=selectedNode.getBoundingClientRect();return {x:r.x+10,y:r.y+r.height/2}})()`);
  await cdp('Input.dispatchMouseEvent',{type:'mousePressed',...point,button:'left',clickCount:3});
  await cdp('Input.dispatchMouseEvent',{type:'mouseReleased',...point,button:'left',clickCount:3});
  await until(`!window.getSelection().isCollapsed`);
  const selection=await evaluate(`window.getSelection().toString()`);
  await evaluate(`window.testStreams.at(-1).onmessage({data:JSON.stringify({service:{state:'selection-refresh-test'},host:'new-host'})})`);
  await pause(500);
  assert.equal(await evaluate(`window.getSelection().toString()`),selection);
  assert.equal(await evaluate(`selectedNode.textContent===statusText&&selectedNode===document.querySelector('.system-grid dd')&&originalSection===document.querySelector('.system-grid section')`),true);
  await evaluate(`window.getSelection().removeAllRanges()`);await until(`document.querySelector('.system-grid dd').textContent==='selection-refresh-test'`);
  assert.equal(await evaluate(`selectedNode===document.querySelector('.system-grid dd')`),true);
  await mkdir((testOutput + '/system-capacity'),{recursive:true});
  await writeFile((testOutput + '/system-capacity/desktop.png'),Buffer.from((await cdp('Page.captureScreenshot',{format:'png',captureBeyondViewport:true})).data,'base64'));
  await cdp('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true});
  await evaluate(`document.querySelector('.database-card').scrollIntoView()`);await pause(300);
  assert.equal(await evaluate(`document.documentElement.scrollWidth<=window.innerWidth`),true);
  await writeFile((testOutput + '/system-capacity/mobile.png'),Buffer.from((await cdp('Page.captureScreenshot',{format:'png'})).data,'base64'));
  assert.equal((await execute(`const r=await fetch('/api/db/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:'{"cap_mib":512}'});return r.status`)),400);
  assert.deepEqual(exceptions,[]);
  console.log('ok - capacity API validation, MiB/GiB conversion, save/readback, navigation persistence, invalid precision, real text selection survives refresh, latest state resumes, stable nodes and mobile layout');
} finally {
 if(ws)ws.close();chrome.kill();await pause(500);const resolved=path.resolve(profile);assert.ok(resolved.startsWith(path.resolve(tmpdir())+path.sep)&&path.basename(resolved).startsWith('ndr-chrome-'));await rm(resolved,{recursive:true,force:true,maxRetries:5,retryDelay:200}).catch(()=>{});
}
