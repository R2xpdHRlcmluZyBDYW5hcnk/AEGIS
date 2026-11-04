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
  await cdp('Runtime.enable'); await cdp('Page.enable');
  await cdp('Emulation.setDeviceMetricsOverride',{width:1440,height:1100,deviceScaleFactor:1,mobile:false});
  await cdp('Page.navigate',{url:'http://127.0.0.1:19090/login'});
  await until(`!!document.querySelector('#password')`);
  await evaluate(`document.querySelector('#password').value='preview-only';document.querySelector('form').submit()`);
  await until(`!!document.querySelector('ndr-chart')`);
  await evaluate(`window.pointerEvents=[];for(const kind of ['pointerdown','pointerup','click'])document.addEventListener(kind,e=>window.pointerEvents.push([kind,e.target.tagName,e.target.textContent.slice(0,80)]),true)`);
  async function pointerClick(selector){
    await pause(350);const point=await evaluate(`(()=>{const e=document.querySelector(${JSON.stringify(selector)});if(!e)throw new Error('Missing '+${JSON.stringify(selector)});e.scrollIntoView({block:'center',inline:'center'});const r=e.getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2}})()`);
    await cdp('Input.dispatchMouseEvent',{type:'mouseMoved',...point});
    await cdp('Input.dispatchMouseEvent',{type:'mousePressed',...point,button:'left',clickCount:1});
    await cdp('Input.dispatchMouseEvent',{type:'mouseReleased',...point,button:'left',clickCount:1});
  }
  for(const page of ['alerts','drops','hunt']){
    await pointerClick('[data-page="'+page+'"]');
    await until(`document.querySelector('ndr-events ndr-table[ng-reflect-id]') || document.querySelector('ndr-events>section:last-of-type ndr-table tbody tr td:not(.empty)')`);
    if(page==='drops')await until(`!!document.querySelector('ndr-events .three-grid>section:nth-child(2) td:not(.empty)')`);
    const selector='ndr-events>section:last-of-type ndr-table tbody tr td:nth-child(3) span';
    await evaluate(`window.pointerOriginalCell=document.querySelector(${JSON.stringify(selector)})`);
    await pointerClick(selector);
    assert.equal(await evaluate(`window.pointerOriginalCell.isConnected`),true,page+' preserves cells during real pointer events');
    const shot=await cdp('Page.captureScreenshot',{format:'png'});await writeFile((testOutput + '/angular/pointer-')+page+'.png',Buffer.from(shot.data,'base64'));
    await until(`!!document.querySelector('ndr-details dialog[open]')`);
    console.log('ok - actual mouse click opens '+page+' detail');
    await pointerClick('ndr-details [aria-label="关闭"]');
  }
  await pointerClick('[data-page="hunt"]');
  await until(`!!document.querySelector('ndr-hunt-query input')`);
  await pointerClick('ndr-hunt-query input');
  await until(`!!document.querySelector('ndr-hunt-query [role="listbox"]')`);
  assert.equal(await evaluate(`getComputedStyle(document.querySelector('.query-options')).backgroundColor`),'rgb(40, 40, 40)');
  await cdp('Input.dispatchKeyEvent',{type:'keyDown',key:'ArrowDown',code:'ArrowDown',windowsVirtualKeyCode:40});
  await cdp('Input.dispatchKeyEvent',{type:'keyUp',key:'ArrowDown',code:'ArrowDown',windowsVirtualKeyCode:40});
  await until(`!!document.querySelector('.query-options button.active')`);
  assert.equal(await evaluate(`getComputedStyle(document.querySelector('.query-options button.active')).backgroundColor`),'rgb(53, 83, 59)');
  const shot=await cdp('Page.captureScreenshot',{format:'png'});await mkdir((testOutput + '/angular'),{recursive:true});await writeFile((testOutput + '/angular/query-menu.png'),Buffer.from(shot.data,'base64'));
  await cdp('Input.dispatchKeyEvent',{type:'keyDown',key:'Enter',code:'Enter',windowsVirtualKeyCode:13});
  await cdp('Input.dispatchKeyEvent',{type:'keyUp',key:'Enter',code:'Enter',windowsVirtualKeyCode:13});
  assert.equal(await evaluate(`document.querySelector('ndr-hunt-query input').value`),'src:192.0.2.0/24');
  assert.equal(await evaluate(`!!document.querySelector('.query-options')`),false);
  console.log('ok - styled Angular query menu and real keyboard selection');
  await pointerClick('[data-page="overview"]');await until(`!!document.querySelector('.engine-counters')`);await pointerClick('.engine-counters summary');
  assert.equal(await evaluate(`getComputedStyle(document.querySelector('.counter-grid')).gridTemplateColumns.split(' ').length`),4);
  assert.equal(await evaluate(`document.querySelector('.engine-counters').textContent.includes('计数自引擎启动累计')`),false);
  assert.equal(await evaluate(`document.querySelector('.engine-counters').textContent.includes('代理 TCP')`),false);
  const counters=await cdp('Page.captureScreenshot',{format:'png'});await writeFile((testOutput + '/angular/engine-counters.png'),Buffer.from(counters.data,'base64'));
  await cdp('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true});
  assert.equal(await evaluate(`getComputedStyle(document.querySelector('.counter-grid')).gridTemplateColumns.split(' ').length`),2);
  console.log('ok - compact four-column counters, two-column mobile layout and removed explanatory text');
  await writeFile((testOutput + '/angular/pointer-results.json'),JSON.stringify({ok:true,realMouseDetails:['alerts','drops','hunt'],cellIdentityPreserved:true,menuKeyboard:true,originalPalette:true,compactCounters:true,uncaughtExceptions:exceptions},null,2));
  assert.deepEqual(exceptions,[]);
} finally {
  if(ws)ws.close();chrome.kill();await pause(500);
  const resolved=path.resolve(profile);assert.ok(resolved.startsWith(path.resolve(tmpdir())+path.sep)&&path.basename(resolved).startsWith('ndr-chrome-'));
  await rm(resolved,{recursive:true,force:true,maxRetries:5,retryDelay:200}).catch(()=>{});
}
