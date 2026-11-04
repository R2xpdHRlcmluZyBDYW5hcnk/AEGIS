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
 await nav('rules');await ruleTab('规则分组');await set('ndr-rules input[type="search"]','stream_tcp');
 await until(`document.querySelector('ndr-rules tbody strong.rule-source')?.textContent==='Snort 内置'`);
 assert.ok(Number(await evaluate(`getComputedStyle(document.querySelector('ndr-rules tbody strong.rule-source')).fontWeight`))>=700);
 await evaluate(`document.querySelector('ndr-rules tbody tr').click()`);await until(`!!document.querySelector('ndr-rule-collection h2 strong.rule-source')`);
 assert.equal(await evaluate(`document.querySelector('ndr-rule-collection h2 strong.rule-source').textContent`),'Snort 内置');
 assert.equal(await evaluate(`[...document.querySelectorAll('ndr-rule-collection tbody strong.rule-source')].every(e=>e.textContent==='Snort 内置')`),true);
 assert.equal(await evaluate(`[...document.querySelectorAll('ndr-rule-collection tbody strong.rule-source')].every(e=>{const r=e.getBoundingClientRect(),cell=e.closest('td').getBoundingClientRect();return r.left>=cell.left&&r.right<=cell.right})`),true);
 await shot('group-details');await evaluate(`document.querySelector('ndr-rule-collection [aria-label="关闭"]').click()`);await until(`!document.querySelector('ndr-rule-collection')`);
 await evaluate(`document.querySelector('ndr-rules tbody input').click()`);await click('抑制告警',`document.querySelector('.selection-bar')`);
 await until(`document.querySelector('ndr-picker .chips strong.rule-source')?.textContent==='Snort 内置'`);
 await shot('selected-group');await click('确认保存',`document.querySelector('ndr-picker')`);await until(`!document.querySelector('ndr-picker')`);
 await ruleTab('告警抑制');await until(`document.querySelector('ndr-rules tbody ndr-rule-target strong.rule-source')?.textContent==='Snort 内置'`);
 assert.equal(await evaluate(`document.querySelector('ndr-rules tbody .badge').textContent.trim()`),'整组策略');
 assert.equal(await evaluate(`document.querySelector('ndr-rules tbody').textContent.includes(String.fromCharCode(183))`),false);
 await shot('governance');
 await nav('hunt');await until(`!!document.querySelector('ndr-events .flow-state')`);
 const borders=await evaluate(`[...document.querySelectorAll('ndr-events .flow-state')].map(e=>({badge:e.classList.contains('badge'),border:getComputedStyle(e).borderTopStyle}))`);
 assert.ok(borders.length);assert.ok(borders.every(e=>e.badge&&e.border==='solid'));
 await evaluate(`document.querySelector('ndr-events .flow-state').closest('tr').click()`);await until(`!!document.querySelector('ndr-details .flow-state')`);
 assert.equal(await evaluate(`[...document.querySelectorAll('ndr-details .flow-state')].every(e=>e.classList.contains('badge')&&getComputedStyle(e).borderTopStyle==='solid')`),true);
 await shot('connection-state');
 await evaluate(`document.querySelector('ndr-details .raw-evidence summary').click()`);
 assert.ok((await evaluate(`document.querySelector('ndr-details .raw-evidence pre').textContent`)).includes('\n  "timestamp":'));
 await shot('formatted-json');
 await evaluate(`document.querySelector('ndr-details [aria-label="关闭"]').click()`);await until(`!document.querySelector('ndr-details ndr-modal')`);
 await set('ndr-events input[aria-label="搜索查询"]','level: *');
 await evaluate(`document.querySelector('ndr-events form').requestSubmit()`);
 await until(`!!document.querySelector('ndr-events tbody tr.clickable')&&!document.querySelector('ndr-events .error')`);
 const levels=await api('/api/hunt?all=1&q=level%3A%20*&view=list');assert.ok(levels.total>0);assert.ok(levels.events.every(e=>['alert','drop'].includes(e.type)));
 const unrated=await api('/api/hunt?all=1&q=level%3Aunknown');assert.ok(unrated.total>0);assert.ok(unrated.events.every(e=>e.sev===0&&e.level==='unknown'));
 const incidents=await api('/api/incidents?window=1440');assert.equal(incidents.incidents[0].sig,'Native reject only');assert.equal(incidents.incidents[0].action,'blocked');
 assert.deepEqual(exceptions,[]);
 console.log('PASS: source labels bold across lists/details/selections/governance, connection states share bordered badges, no generated middle-dot separators');
} finally {
 if(ws)ws.close();chrome.kill();await pause(500);
 const resolved=path.resolve(profile);
 assert.ok(path.dirname(resolved)===path.resolve(tmpdir())&&path.basename(resolved).startsWith('ndr-chrome-'));
 await rm(resolved,{recursive:true,force:true,maxRetries:5,retryDelay:200});
}
