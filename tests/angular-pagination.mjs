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
 async function nextPage(scope){
  await evaluate(`(()=>{const t=${scope};t.querySelector('.table-scroll').scrollTop=99999;const m=t.closest('.modal-scroll')||document.querySelector('main');m.scrollTop=99999})()`);
  const before=await evaluate(`${scope}.querySelector('tbody tr').textContent`);
  await click('下一页 →',scope);
  await until(`${scope}.querySelector('.table-scroll').getAttribute('aria-busy')==='false'&&${scope}.querySelector('tbody tr').textContent!==${JSON.stringify(before)}`);
  await pause(400);
  const position=await evaluate(`(()=>{const t=${scope},row=t.querySelector('tbody tr'),sc=t.querySelector('.table-scroll'),m=t.closest('.modal-scroll')||document.querySelector('main'),h=t.querySelector('thead').getBoundingClientRect().height,mh=m.querySelector(':scope > .modal-head')?.getBoundingClientRect().height||0;return {inner:row.getBoundingClientRect().top-sc.getBoundingClientRect().top-sc.clientTop-h,outer:row.getBoundingClientRect().top-m.getBoundingClientRect().top-m.clientTop-h-mh,main:document.querySelector('main').scrollTop}})()`);
  assert.ok(Math.abs(position.inner)<=3,JSON.stringify(position));
  assert.ok(position.outer>=-3&&position.outer<700,JSON.stringify(position));
 }
 await nav('rules');await ruleTab('检测签名');
 await nextPage(`document.querySelector('ndr-rules ndr-table')`);
 await ruleTab('规则分组');await set('ndr-rules input[type="search"]','emerging-scan');
 await until(`document.querySelector('ndr-rules tbody')?.textContent.includes('emerging-scan')`);
 await evaluate(`document.querySelector('ndr-rules tbody tr').click()`);await until(`!!document.querySelector('ndr-rule-collection tbody tr.clickable')`);
 await nextPage(`document.querySelector('ndr-rule-collection ndr-table')`);
 await evaluate(`document.querySelector('ndr-rule-collection [aria-label="关闭"]').click()`);await until(`!document.querySelector('ndr-rule-collection')`);
 await ruleTab('禁用策略');await click('＋ 新建',`document.querySelector('ndr-rules')`);await until(`!!document.querySelector('ndr-picker tbody tr')`);
 await nextPage(`document.querySelector('ndr-picker ndr-table')`);
 assert.deepEqual(exceptions,[]);
 console.log('PASS: page changes align the new first row in server-paged tables, detail modals and candidate pickers');
} finally {
 if(ws)ws.close();chrome.kill();await pause(500);
 const resolved=path.resolve(profile);
 assert.ok(path.dirname(resolved)===path.resolve(tmpdir())&&path.basename(resolved).startsWith('ndr-chrome-'));
 await rm(resolved,{recursive:true,force:true,maxRetries:5,retryDelay:200});
}
