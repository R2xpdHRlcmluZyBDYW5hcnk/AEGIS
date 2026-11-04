// Desktop regression with synthetic transport responses. Start serve_preview.py first.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdtemp,readFile,rm,mkdir,writeFile} from 'node:fs/promises';
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
 const output=process.env.NDR_TEST_OUTPUT;async function shot(name){if(!output)return;await pause(500);await mkdir(path.join(output,'rule-styles'),{recursive:true});await writeFile(path.join(output,'rule-styles',name+'.png'),Buffer.from((await cdp('Page.captureScreenshot',{format:'png'})).data,'base64'));}
 await nav('system');await until(`!!document.querySelector('ndr-system .database-card')`);
 let attempt=0,polls=0;const job='b'.repeat(32);
 async function respond(requestId,value){await cdp('Fetch.fulfillRequest',{requestId,responseCode:200,responseHeaders:[{name:'Content-Type',value:'application/json'}],body:Buffer.from(JSON.stringify(value)).toString('base64')});}
 intercept=async p=>{
  const url=new URL(p.request.url);
  if(url.pathname==='/api/db/clear'&&p.request.method==='POST'){attempt++;polls=0;return respond(p.requestId,{ok:true,pending:true,reset_id:job});}
  if(url.pathname==='/api/db/clear/status'){
   polls++;return respond(p.requestId,{reset:{id:job,state:polls===1?'running':attempt===1?'failed':'done',error:attempt===1&&polls>1?'synthetic recovery error':''}});
  }
  return cdp('Fetch.continueRequest',{requestId:p.requestId});
 };
 await cdp('Fetch.enable',{patterns:[{urlPattern:'*/api/db/clear*',requestStage:'Request'}]});
 await click('清空历史事件',`document.querySelector('ndr-system')`);
 await until(`!!document.querySelector('ndr-app > ndr-modal .modal-actions')||!!document.querySelector('.modal-actions .danger-button')`);
 const message=await evaluate(`document.querySelector('ndr-modal .modal-content').textContent`);
 assert.ok(message.includes('暂停检测')&&message.includes('原始日志')&&message.includes('重新登录'));
 await click('取消',`document.querySelector('ndr-modal')`);await until(`!document.querySelector('ndr-modal')`);assert.equal(attempt,0);
 await click('清空历史事件',`document.querySelector('ndr-system')`);await click('确认',`document.querySelector('ndr-modal')`);
 await until(`document.body.textContent.includes('synthetic recovery error')`);assert.ok(polls>=2);
 await click('清空历史事件',`document.querySelector('ndr-system')`);await click('确认',`document.querySelector('ndr-modal')`);
 await until(`!!document.querySelector('ndr-system .database-card')&&![...document.querySelectorAll('ndr-system button')].find(e=>e.textContent.trim()==='清空历史事件')?.disabled`);
 for(let i=0;i<80&&polls<2;i++)await pause(100);
 assert.equal(attempt,2);assert.ok(polls>=2);await pause(700);
 await until(`!!document.querySelector('[data-page="system"]')&&performance.getEntriesByType('navigation')[0]?.type==='reload'`);
 assert.deepEqual(exceptions,[]);
 console.log('PASS: explicit history confirmation, cancellation, queued status polling, failure recovery and successful reload');
} finally {
 if(ws)ws.close();chrome.kill();await pause(500);
 const resolved=path.resolve(profile);
 assert.ok(path.dirname(resolved)===path.resolve(tmpdir())&&path.basename(resolved).startsWith('ndr-chrome-'));
 await rm(resolved,{recursive:true,force:true,maxRetries:5,retryDelay:200});
}
