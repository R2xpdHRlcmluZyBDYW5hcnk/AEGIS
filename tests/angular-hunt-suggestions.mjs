import {testOutput} from './test-output.mjs';
// Dependency-free Chrome DevTools smoke test. Start serve_preview.py first.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, writeFile, mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
const baseUrl=process.env.NDR_PREVIEW_URL||'http://127.0.0.1:19090';
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
  const pending = new Map(), exceptions = [], streamFailures=[];
  let id = 0;
  ws.onmessage = ({ data }) => {
    const message = JSON.parse(data);
    if(message.method==='Network.responseReceived'&&message.params.response.url.includes('/api/stream?')&&message.params.response.status>=400)streamFailures.push(message.params.response.status);
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
  await cdp('Page.navigate',{url:baseUrl+'/login'});await until(`!!document.querySelector('#password')`);
  await evaluate(`document.querySelector('#password').value='preview-only';document.querySelector('form').submit()`);await until(`!!document.querySelector('ndr-chart')`);
  async function pointerClick(selector){
    await pause(350);const point=await evaluate(`(()=>{const e=document.querySelector(${JSON.stringify(selector)});if(!e)throw new Error('Missing '+${JSON.stringify(selector)});e.scrollIntoView({block:'center',inline:'center'});const r=e.getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2}})()`);
    await cdp('Input.dispatchMouseEvent',{type:'mouseMoved',...point});
    await cdp('Input.dispatchMouseEvent',{type:'mousePressed',...point,button:'left',clickCount:1});
    await cdp('Input.dispatchMouseEvent',{type:'mouseReleased',...point,button:'left',clickCount:1});
  }

  await pointerClick('[data-page="hunt"]');await until(`!!document.querySelector('ndr-hunt-query input')`);
  await pointerClick('ndr-hunt-query input');await until(`document.querySelectorAll('.query-options button').length>15`);
  const expected=await evaluate(`(async()=>{const d=await(await fetch('/api/hunt/schema')).json();return [...new Set([...d.fields.map(f=>f.name),'rrname'])].sort();})()`);
  const offered=await evaluate(`[...document.querySelectorAll('.query-options button strong')].map(e=>e.textContent.split(':')[0]).sort()`);
  assert.deepEqual(offered,expected);
  assert.ok(offered.includes('level'));assert.ok(!offered.includes('sev'));
  // ArrowUp from an unselected list reaches its final item, beyond the old cutoff.
  await cdp('Input.dispatchKeyEvent',{type:'keyDown',key:'ArrowUp',code:'ArrowUp',windowsVirtualKeyCode:38});await cdp('Input.dispatchKeyEvent',{type:'keyUp',key:'ArrowUp',code:'ArrowUp',windowsVirtualKeyCode:38});
  await until(`document.querySelector('.query-options button.active')?.textContent.includes('rrname:')`);
  await cdp('Input.dispatchKeyEvent',{type:'keyDown',key:'Enter',code:'Enter',windowsVirtualKeyCode:13});await cdp('Input.dispatchKeyEvent',{type:'keyUp',key:'Enter',code:'Enter',windowsVirtualKeyCode:13});
  assert.equal(await evaluate(`document.querySelector('ndr-hunt-query input').value`),'rrname:');
  async function type(value){await evaluate(`(()=>{const e=document.querySelector('ndr-hunt-query input');e.value=${JSON.stringify(value)};e.dispatchEvent(new Event('input',{bubbles:true}));})()`);}
  await type('证书');await until(`document.querySelectorAll('.query-options button').length===3`);
  assert.deepEqual(await evaluate(`[...document.querySelectorAll('.query-options strong')].map(e=>e.textContent.split(':')[0]).sort()`),['issuer','subject','validation_status']);
  for(const field of ['anom','tlsver','rrname','level']){await type(field);await until(`document.querySelector('.query-options strong')?.textContent.startsWith('${field}:')`);}
  await type('sev');assert.equal(await evaluate(`!!document.querySelector('.query-options')`),false);
  const choices=await evaluate(`(async()=>{const data=await(await fetch('/api/hunt/schema')).json();return data.fields.filter(f=>f.values);})()`);
  for(const field of choices){
    await type(field.name+':');
    await until(`document.querySelectorAll('.query-options button').length===${field.values.length}`);
    const examples=await evaluate(`[...document.querySelectorAll('.query-options strong')].map(e=>e.textContent)`);
    assert.deepEqual(examples,field.values.map(item=>field.name+': '+(/[^a-zA-Z0-9_.-]/.test(item.value)?JSON.stringify(item.value):item.value)),field.name);
  }
  for(const [typed,inserted] of [['session_event:sta','session_event: start'],['type: tls AND tlsver:','type: tls AND tlsver: "TLS 1.3"'],['type:sess','type: session']]){
    await type(typed);await until(`!!document.querySelector('.query-options button')`);
    await pointerClick('.query-options button');
    assert.equal(await evaluate(`document.querySelector('ndr-hunt-query input').value`),inserted);
    const result=await evaluate(`(async()=>{const d=await(await fetch('/api/hunt?'+new URLSearchParams({q:${JSON.stringify(inserted)},window:'1440',limit:'1',source:'db'}))).json();return {error:d.error,total:d.total,truncated:d.truncated};})()`);
    assert.ok(!result.error,inserted);assert.equal(result.truncated,false,inserted);
  }
  const states=await evaluate(`(async()=>{const d=await(await fetch('/api/hunt?'+new URLSearchParams({q:'state:closed',window:'1440',limit:'1',source:'db'}))).json();return {total:d.total,error:d.error};})()`);
  assert.equal(states.total,2);assert.ok(!states.error);
  await type('type:tls AND issuer');await until(`document.querySelector('.query-options strong')?.textContent.startsWith('issuer:')`);
  await pointerClick('.query-options button');assert.equal(await evaluate(`document.querySelector('ndr-hunt-query input').value`),'type:tls AND issuer:');
  await type('status:[400 TO 499]');assert.equal(await evaluate(`!!document.querySelector('.query-options')`),false);
  const range=await evaluate(`(async()=>{const d=await(await fetch('/api/hunt?'+new URLSearchParams({q:'status:[400 TO 599]',window:'1440',limit:'1'}))).json();return d;})()`);assert.ok(!range.error);
  const invalid=await evaluate(`(async()=>{const d=await(await fetch('/api/hunt?'+new URLSearchParams({q:'sqlite_master:*',window:'1440',limit:'1'}))).json();return d;})()`);assert.ok(invalid.error);
  await type('ip_version: 4 and proto: tcp');await evaluate(`document.querySelector('ndr-events form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}))`);
  await until(`document.querySelector('ndr-events .error[role="alert"]')?.textContent.includes('连接词必须大写')`);
  await type('ip_version:4 AND proto:tcp');await evaluate(`document.querySelector('ndr-events form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}))`);
  await until(`!document.querySelector('ndr-events .error[role="alert"]')&&document.querySelectorAll('ndr-events tbody tr').length>1`);
  await evaluate(`document.querySelector('ndr-events .filter-line input[type="checkbox"]').click()`);
  await until(`document.querySelector('ndr-events .table-scroll')?.getAttribute('aria-busy')==='false'`);
  for(let index=0;index<16;index++){
    const direction=index%8<4?1:0;
    await evaluate(`document.querySelectorAll('ndr-events .pager>div>button')[${direction}].click()`);
    await until(`document.querySelector('ndr-events .table-scroll')?.getAttribute('aria-busy')==='false'&&document.querySelectorAll('ndr-events tbody tr').length>1`);
    assert.equal(await evaluate(`!!document.querySelector('ndr-events .error[role="alert"]')`),false,'rapid paging keeps its realtime subscription healthy');
  }
  assert.deepEqual(streamFailures,[],'closed subscriptions release capacity during rapid paging');
  const payload='fixture <img src=x onerror="window.ndrInjected=true">';
  const injection=await evaluate(`(async()=>{const q='appid_client:'+JSON.stringify(${JSON.stringify(payload)}),d=await(await fetch('/api/hunt?'+new URLSearchParams({q,window:'1440',limit:'2'}))).json();return d;})()`);assert.ok(!injection.error);assert.equal(injection.total,1);
  await type('type:session AND appid_service:HTTPS');await evaluate(`document.querySelector('ndr-events form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}))`);
  await until(`document.querySelector('ndr-events tbody tr')?.textContent.includes('HTTPS')`);
  await pointerClick('ndr-events tbody tr');await until(`document.querySelector('ndr-details')?.textContent.includes('OpenAppID')`);
  assert.ok(await evaluate(`document.querySelector('ndr-details').textContent.includes(${JSON.stringify(payload)})`));
  assert.equal(await evaluate(`!!window.ndrInjected||!!document.querySelector('ndr-details img[src="x"]')`),false,'untrusted application names render as text');
  assert.deepEqual(exceptions,[]);
  console.log('ok - every query field and configured value is offered, quoted values and compound insertion query successfully, state filtering matches the fixture');
} finally {
 if(ws)ws.close();chrome.kill();await pause(500);const resolved=path.resolve(profile);assert.ok(resolved.startsWith(path.resolve(tmpdir())+path.sep)&&path.basename(resolved).startsWith('ndr-chrome-'));await rm(resolved,{recursive:true,force:true,maxRetries:5,retryDelay:200}).catch(()=>{});
}
