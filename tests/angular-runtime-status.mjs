// Desktop regression with synthetic transport responses. Start serve_preview.py first.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
const profile=await mkdtemp(path.join(tmpdir(),'ndr-chrome-'));
const chrome=spawn(process.env.CHROME_PATH||'C:/Program Files/Google/Chrome/Application/chrome.exe',[
 '--headless=new','--disable-gpu','--no-first-run','--no-default-browser-check',
 '--remote-debugging-port=0','--remote-allow-origins=*',`--user-data-dir=${profile}`,'about:blank'
],{windowsHide:true,stdio:'ignore'});
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
let ws;
try {
 let port;
 for(let i=0;i<100;i++){try{port=Number((await readFile(path.join(profile,'DevToolsActivePort'),'utf8')).split('\n')[0]);break;}catch{await pause(100);}}
 assert.ok(port,'Chrome starts');
 const tab=await(await fetch(`http://127.0.0.1:${port}/json/new?about:blank`,{method:'PUT'})).json();
 ws=new WebSocket(tab.webSocketDebuggerUrl);
 await new Promise((resolve,reject)=>{ws.onopen=resolve;ws.onerror=reject;});
 const pending=new Map(),exceptions=[];
 let id=0,intercept=async p=>cdp('Fetch.continueRequest',{requestId:p.requestId});
 ws.onmessage=({data})=>{
  const message=JSON.parse(data);
  if(message.method==='Fetch.requestPaused')void intercept(message.params).catch(e=>exceptions.push(e.message));
  if(message.method==='Runtime.exceptionThrown')exceptions.push(message.params.exceptionDetails);
  if(message.id&&pending.has(message.id)){const {resolve,reject}=pending.get(message.id);pending.delete(message.id);message.error?reject(new Error(JSON.stringify(message.error))):resolve(message.result);}
 };
 function cdp(method,params={}){const sequence=++id;return new Promise((resolve,reject)=>{
  const timer=setTimeout(()=>{pending.delete(sequence);reject(new Error('CDP timeout: '+method));},15000);
  pending.set(sequence,{resolve:v=>{clearTimeout(timer);resolve(v);},reject:e=>{clearTimeout(timer);reject(e);}});
  ws.send(JSON.stringify({id:sequence,method,params}));
 });}
 async function evaluate(expression){const r=await cdp('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});if(r.exceptionDetails)throw new Error(JSON.stringify(r.exceptionDetails));return r.result.value;}
 async function until(expression){for(let i=0;i<100;i++){if(await evaluate(expression))return;await pause(100);}throw new Error('Timed out: '+expression+'\n'+await evaluate('document.body.innerText.slice(-3000)'));}
 async function click(text,scope='document'){const selector=`[...${scope}.querySelectorAll('button')].find(b=>b.textContent.trim()===${JSON.stringify(text)}&&!b.disabled)`;await until(`!!(${selector})`);await evaluate(`(${selector}).click()`);}
 async function set(selector,value){await evaluate(`(()=>{const e=document.querySelector(${JSON.stringify(selector)});e.value=${JSON.stringify(value)};e.dispatchEvent(new Event('input',{bubbles:true}));})()`);}
 async function nav(page){await evaluate(`document.querySelector('[data-page="${page}"]').click()`);await until(`location.hash==='#${page}'`);}
 async function ruleTab(title){await click(title,`document.querySelector('ndr-rules .tabs')`);await until(`document.querySelector('ndr-rules .tabs button.active')?.textContent.trim()===${JSON.stringify(title)}&&document.querySelector('ndr-rules ndr-table .table-scroll')?.getAttribute('aria-busy')==='false'`);}
 async function api(url){return evaluate(`fetch(${JSON.stringify(url)}).then(r=>r.json())`);}
 await cdp('Runtime.enable');await cdp('Page.enable');await cdp('Network.enable');
 await cdp('Emulation.setDeviceMetricsOverride',{width:1440,height:1100,deviceScaleFactor:1,mobile:false});
 const base=process.env.NDR_PREVIEW_URL||'http://127.0.0.1:19090';
 await cdp('Page.navigate',{url:base+'/login'});await until(`!!document.querySelector('#password')`);
 await set('#password','preview-only');await evaluate(`document.querySelector('form').submit()`);
 await until(`!!document.querySelector('[data-page="rules"]')`);
 await evaluate(`fetch('/__test/reset',{method:'POST',headers:{'X-Requested-With':'ips-web'}}).then(r=>r.json())`);
 await nav('rules');await click('应用更改 →');
 await until(`document.querySelector('.rule-summary')?.textContent.includes('规则校验与应用中')`);
 await until(`fetch('/api/actions/status').then(r=>r.json()).then(d=>d.state==='running')`);
 await nav('system');await until(`!!document.querySelector('ndr-system .system-grid')&&document.querySelector('ndr-system .telemetry-status')?.textContent.includes('规则任务进行中')`);
 assert.equal(await evaluate(`document.querySelector('ndr-system>.error')?.textContent||''`),'');
 assert.equal(await evaluate(`document.querySelector('.telemetry-status').textContent.includes(String.fromCharCode(183))`),false);
 await nav('overview');await until(`!!document.querySelector('[data-testid="alerts-total"]')&&document.querySelector('ndr-overview .telemetry-status')?.textContent.includes('规则任务进行中')`);
 assert.ok((await api('/api/overview')).security.total>0);
 assert.equal(await evaluate(`document.querySelector('.telemetry-status').textContent.includes(String.fromCharCode(183))`),false);
 await nav('hunt');await until(`!!document.querySelector('ndr-events tbody tr')`);
 assert.equal((await api('/api/actions/status')).state,'running','navigation must finish before releasing reload');
 await nav('rules');await until(`document.querySelector('.rule-summary')?.textContent.includes('规则校验与应用中')`);
 await evaluate(`fetch('/__test/release-reload',{method:'POST',headers:{'X-Requested-With':'ips-web'}}).then(r=>r.json())`);
 await until(`document.querySelector('.job-log')?.textContent.includes('规则已校验并完成热重载')`);
 await nav('system');await until(`!!document.querySelector('ndr-system .system-grid')&&!document.querySelector('ndr-system .telemetry-status')`);
 assert.deepEqual(exceptions,[]);
 console.log('PASS: blocked native reload leaves system, overview, history and job status navigable; sampling timestamp visible and fresh sampling resumes');
} finally {
 if(ws)ws.close();chrome.kill();await pause(500);
 const resolved=path.resolve(profile);
 assert.ok(path.dirname(resolved)===path.resolve(tmpdir())&&path.basename(resolved).startsWith('ndr-chrome-'));
 await rm(resolved,{recursive:true,force:true,maxRetries:5,retryDelay:200});
}
