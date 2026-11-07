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
  const pending = new Map(), exceptions = [], requests=[];
  let id = 0;
  ws.onmessage = ({ data }) => {
    const message = JSON.parse(data);
    if(message.method==='Network.requestWillBeSent')requests.push(message.params.request.url);
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
  await cdp('Runtime.enable');await cdp('Page.enable');await cdp('Network.enable');
  await cdp('Emulation.setDeviceMetricsOverride',{width:1440,height:1100,deviceScaleFactor:1,mobile:false});
  await cdp('Page.navigate',{url:'http://127.0.0.1:19093/login'});await until(`!!document.querySelector('#password')`);
  await evaluate(`document.querySelector('#password').value='preview-only';document.querySelector('form').submit()`);await until(`!!document.querySelector('ndr-chart')`);
  async function pointerClick(selector){
    await pause(350);const point=await evaluate(`(()=>{const e=document.querySelector(${JSON.stringify(selector)});if(!e)throw new Error('Missing '+${JSON.stringify(selector)});e.scrollIntoView({block:'center',inline:'center'});const r=e.getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2}})()`);
    await cdp('Input.dispatchMouseEvent',{type:'mouseMoved',...point});
    await cdp('Input.dispatchMouseEvent',{type:'mousePressed',...point,button:'left',clickCount:1});
    await cdp('Input.dispatchMouseEvent',{type:'mouseReleased',...point,button:'left',clickCount:1});
  }

  async function fill(selector,value,event='input'){await evaluate(`(()=>{const e=document.querySelector(${JSON.stringify(selector)});e.value=${JSON.stringify(value)};e.dispatchEvent(new Event(${JSON.stringify(event)},{bubbles:true}))})()`);}
  for(const mode of ['alerts','hunt','drops']){
   await pointerClick('[data-page="'+mode+'"]');await until(`!!document.querySelector('ndr-events input[aria-label="搜索查询"]')`);
   await until(`!!document.querySelector('ndr-events tbody tr.clickable')`);
   await fill('ndr-events input[aria-label="搜索查询"]',mode==='hunt'?'type:tls AND sni:no-such-host.invalid':'no-such-host.invalid');
   if(mode==='alerts')await fill('ndr-events [name="severity"]','1','change');
   if(mode!=='hunt')await fill('ndr-events [name="protocol"]','UDP','change');
   if(mode==='hunt')await pointerClick('ndr-events .filter-line>label:last-child input');
   await pointerClick('ndr-events form button[type="submit"]');await pause(200);
   await fill('ndr-events ndr-range select','custom','change');
   await pointerClick('ndr-events ndr-range .quiet');await until(`!!document.querySelector('ndr-events ndr-range .error')`);
   const marker=requests.length;
   await pointerClick('ndr-events ndr-range .text-button');
   await until(`!!document.querySelector('ndr-events tbody tr.clickable')`);
   assert.equal(await evaluate(`document.querySelector('ndr-events input[aria-label="搜索查询"]').value`),'');
   assert.equal(await evaluate(`document.querySelector('ndr-events ndr-range select').value`),'60');
   assert.equal(await evaluate(`document.querySelectorAll('ndr-events ndr-range input').length`),0);
   assert.equal(await evaluate(`document.querySelector('ndr-events .filter-line>label input').checked`),mode!=='hunt');
   assert.equal(await evaluate(`document.querySelectorAll('ndr-events .error').length`),0);
   if(mode==='hunt')assert.equal(await evaluate(`document.querySelector('ndr-events .filter-line>label:last-child input').checked`),false);
   if(mode==='alerts')assert.equal(await evaluate(`document.querySelector('ndr-events [name="severity"]').value`),'');
   if(mode!=='hunt')assert.equal(await evaluate(`document.querySelector('ndr-events [name="protocol"]').value`),'');
   const endpoint=mode==='alerts'?'/api/incidents':mode==='hunt'?'/api/hunt':'/api/events';
   const resetRequests=requests.slice(marker).map(u=>new URL(u)).filter(u=>u.pathname===endpoint);
   assert.equal(resetRequests.length,1,'reset makes one result request: '+mode);
   const params=resetRequests[0].searchParams;
   assert.equal(params.get('window'),'60');assert.equal(params.get('offset'),'0');
   for(const key of ['q','sev','proto','from','to'])assert.equal(params.has(key),false,key+' cleared for '+mode);
   if(mode==='hunt')assert.equal(params.get('icase'),'1');
   await pointerClick('[data-page="overview"]');await until(`!!document.querySelector('ndr-chart')`);
   await pointerClick('[data-page="'+mode+'"]');await until(`!!document.querySelector('ndr-events tbody tr.clickable')`);
   assert.equal(await evaluate(`document.querySelector('ndr-events input[aria-label="搜索查询"]').value`),'');
   assert.equal(await evaluate(`document.querySelector('ndr-events ndr-range select').value`),'60');
   console.log('ok - '+mode+': reset clears query, filters, invalid custom range, options; reloads default 1-hour results once; stays reset after navigating away and back');
  }
  assert.deepEqual(exceptions,[]);
} finally {
 if(ws)ws.close();chrome.kill();await pause(500);const resolved=path.resolve(profile);assert.ok(resolved.startsWith(path.resolve(tmpdir())+path.sep)&&path.basename(resolved).startsWith('ndr-chrome-'));await rm(resolved,{recursive:true,force:true,maxRetries:5,retryDelay:200}).catch(()=>{});
}
