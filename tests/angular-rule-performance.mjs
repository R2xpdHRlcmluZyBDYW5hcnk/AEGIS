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
 const pending=new Map(),exceptions=[],requests=[],failures=[];
 let id=0,intercept=async p=>cdp('Fetch.continueRequest',{requestId:p.requestId});
 ws.onmessage=({data})=>{
  const message=JSON.parse(data);
  if(message.method==='Fetch.requestPaused')void intercept(message.params).catch(e=>exceptions.push(e.message));
  if(message.method==='Network.requestWillBeSent')requests.push({url:message.params.request.url,method:message.params.request.method,id:message.params.requestId});
  if(message.method==='Network.loadingFailed')failures.push(message.params);
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
 const queries=from=>requests.slice(from).filter(r=>r.method==='GET'&&new URL(r.url).pathname.startsWith('/api/rules'));
 let from=requests.length;
 await nav('rules');await until(`document.querySelector('ndr-rules .table-scroll')?.getAttribute('aria-busy')==='false'`);
 assert.deepEqual(queries(from).map(r=>new URL(r.url).pathname),['/api/rules/page']);
 for(const title of ['规则分组','禁用策略','规则源']){
  from=requests.length;await ruleTab(title);
  assert.deepEqual(queries(from).map(r=>new URL(r.url).pathname),['/api/rules/page'],title);
 }
 let held;
 intercept=async p=>{if(new URL(p.request.url).searchParams.get('tab')==='catalog')held=p.requestId;else await cdp('Fetch.continueRequest',{requestId:p.requestId});};
 await cdp('Fetch.enable',{patterns:[{urlPattern:'*/api/rules/page*',requestStage:'Request'}]});
 from=requests.length;await click('检测签名',`document.querySelector('ndr-rules .tabs')`);
 for(let i=0;i<100&&!held;i++)await pause(20);
 assert.ok(held,'catalog request is held while switching tabs');
 const cancelled=queries(from).find(r=>new URL(r.url).searchParams.get('tab')==='catalog');
 await ruleTab('规则分组');
 for(let i=0;i<100&&!failures.some(f=>f.requestId===cancelled?.id&&f.canceled);i++)await pause(20);
 assert.ok(failures.some(f=>f.requestId===cancelled?.id&&f.canceled),'superseded HTTP request is aborted');
 await cdp('Fetch.disable');intercept=async p=>cdp('Fetch.continueRequest',{requestId:p.requestId});
 assert.equal(await evaluate(`!!document.querySelector('ndr-rules .error')`),false,'cancellation does not show a load error');
 await ruleTab('禁用策略');await click('＋ 新建',`document.querySelector('ndr-rules')`);await until(`!!document.querySelector('ndr-picker tbody input')`);
 await evaluate(`document.querySelector('ndr-picker tbody input').click()`);
 from=requests.length;await click('确认保存',`document.querySelector('ndr-picker')`);await until(`!document.querySelector('ndr-picker')&&document.querySelector('ndr-rules .table-scroll')?.getAttribute('aria-busy')==='false'`);
 assert.equal(queries(from).some(r=>new URL(r.url).pathname==='/api/rules/governance'),false);
 assert.equal(queries(from).filter(r=>new URL(r.url).pathname==='/api/rules/page').length,1);
 from=requests.length;await click('↻ 刷新');await until(`document.querySelector('ndr-rules .table-scroll').getAttribute('aria-busy')==='false'`);
 assert.deepEqual(queries(from).map(r=>new URL(r.url).pathname),['/api/rules/page']);
 assert.deepEqual(exceptions,[]);
 console.log('PASS: one query per load/tab/refresh/save; superseded HTTP request aborted; no cancellation error; source scheduling shares the page response');
} finally {
 if(ws)ws.close();chrome.kill();await pause(500);
 const resolved=path.resolve(profile);
 assert.ok(path.dirname(resolved)===path.resolve(tmpdir())&&path.basename(resolved).startsWith('ndr-chrome-'));
 await rm(resolved,{recursive:true,force:true,maxRetries:5,retryDelay:200});
}
