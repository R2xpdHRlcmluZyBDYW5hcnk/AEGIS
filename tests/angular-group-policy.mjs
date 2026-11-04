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
 await nav('rules');
 const jobBeforeEdits=await api('/api/actions/status');
 const selectors=['group-source:snort%2Flightspd:browser-chrome','group-source:snort%2Fregistered:browser-chrome'];
 async function addGroup(tab,selector){
  await ruleTab(tab);await click('＋ 新建');await until(`!!document.querySelector('ndr-picker')`);
  await evaluate(`(()=>{const e=document.querySelector('[aria-label="选择对象类型"]');e.value='group';e.dispatchEvent(new Event('change',{bubbles:true}));})()`);
  await set('ndr-picker input[type="search"]','browser-chrome');
  await until(`document.querySelectorAll('ndr-picker tbody input').length===${selector===selectors[0]?2:1}`);
  await evaluate(`document.querySelector('ndr-picker tbody input[aria-label="选择 ${selector}"]').click()`);
  await click('确认保存',`document.querySelector('ndr-picker')`);await until(`!document.querySelector('ndr-picker')`);
 }
 for(const tab of ['禁用策略','阻断动作','告警抑制'])for(const selector of selectors)await addGroup(tab,selector);
 let gov=await api('/api/rules/governance');
 assert.deepEqual(gov.disable.map(r=>r.value).sort(),selectors.slice().sort());
 assert.deepEqual(gov.drop.map(r=>r.value).sort(),selectors.slice().sort());
 assert.deepEqual(gov.suppress_groups.map(r=>r.selector).sort(),selectors.slice().sort());
 for(const tab of ['禁用策略','阻断动作','告警抑制']){
  await ruleTab(tab);
  await until(`document.querySelectorAll('ndr-rules tbody input').length===2`);
  await evaluate(`[...document.querySelectorAll('ndr-rules tbody tr')].find(r=>r.textContent.includes('snort/lightspd')).querySelector('input').click()`);
  await click('删除',`document.querySelector('.selection-bar')`);await click('确认',`document.querySelector('dialog')`);
  await until(`document.querySelectorAll('ndr-rules tbody input').length===1&&document.querySelector('ndr-rules tbody').textContent.includes('snort/registered')`);
 }
 gov=await api('/api/rules/governance');assert.equal(gov.suppress.length,0);
 assert.deepEqual(gov.disable.map(r=>r.value),[selectors[1]]);assert.deepEqual(gov.drop.map(r=>r.value),[selectors[1]]);
 assert.deepEqual(gov.suppress_groups.map(r=>r.selector),[selectors[1]]);
 assert.equal(gov.suppress_groups[0].total,3);
 await ruleTab('规则分组');await set('ndr-rules input[type="search"]','browser-chrome');
 await until(`document.querySelectorAll('ndr-rules tbody input').length===2`);
 await evaluate(`document.querySelectorAll('ndr-rules tbody input').forEach(e=>e.click())`);
 await until(`document.querySelector('.selection-bar').textContent.includes('已选 2')`);
 const jobAfterEdits=await api('/api/actions/status');
 assert.deepEqual({...jobAfterEdits,pending:undefined},{...jobBeforeEdits,pending:undefined});
 assert.equal(jobAfterEdits.pending,true);
 const systemFixture={service:{state:'active',pid:123,uptime:90,memory:4096,cpu_seconds:0},engine:{version:'test',uptime:90,reload_time_ms:null,error:'fixture socket unavailable'},ruleset:{rules_loaded:3,rules_loaded_source:'rule_files',rules_failed:null,rules_skipped:null},counters:{tcp:{memory:8192},flow:{memuse:null}},storage:{logs:[]}};
 intercept=async p=>{
  const url=new URL(p.request.url),stream=url.pathname==='/api/stream'&&url.searchParams.get('topic')==='system';
  if(url.pathname==='/api/system'||stream)return cdp('Fetch.fulfillRequest',{requestId:p.requestId,responseCode:200,responseHeaders:[{name:'Content-Type',value:stream?'text/event-stream':'application/json'}],body:Buffer.from(stream?'data: '+JSON.stringify(systemFixture)+'\n\n':JSON.stringify(systemFixture)).toString('base64')});
  return cdp('Fetch.continueRequest',{requestId:p.requestId});
 };
 await cdp('Fetch.enable',{patterns:[{urlPattern:'*/api/system*'},{urlPattern:'*/api/stream*'}]});
 await nav('system');await until(`document.querySelector('ndr-system')?.textContent.includes('fixture socket unavailable')`);
 const readings=await evaluate(`Object.fromEntries([...document.querySelectorAll('.key-values dt')].map(e=>[e.textContent,e.nextElementSibling.textContent]))`);
 assert.equal(readings['CPU 累计秒'],'0');assert.equal(readings['PID'],'123');
 assert.equal(readings['上次重载 ms'],'引擎未提供');assert.equal(readings['流表内存'],'引擎未提供');
 assert.equal(readings['失败 / 跳过'],'未提供 / 未提供');assert.equal(readings['配置文本规则'],'3');
 assert.ok(readings['TCP 流模块内存'].includes('8'));
 assert.deepEqual(exceptions,[]);
 console.log('PASS: same-name source groups stay independent in add/delete/selection for disable/action/suppression; system distinguishes zero, unsupported and errors');
} finally {
 if(ws)ws.close();chrome.kill();await pause(500);
 const resolved=path.resolve(profile);
 assert.ok(path.dirname(resolved)===path.resolve(tmpdir())&&path.basename(resolved).startsWith('ndr-chrome-'));
 await rm(resolved,{recursive:true,force:true,maxRetries:5,retryDelay:200});
}
