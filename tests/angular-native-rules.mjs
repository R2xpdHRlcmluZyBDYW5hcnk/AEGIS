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
 await ruleTab('规则分组');
 await set('ndr-rules input[type="search"]','stream_tcp');
 await until(`document.querySelector('ndr-rules tbody')?.textContent.includes('TCP 流检查')`);
 await evaluate(`document.querySelector('ndr-rules tbody input').click()`);
 assert.equal(await evaluate(`[...document.querySelectorAll('.selection-bar button')].find(b=>b.textContent.trim()==='禁用').disabled`),false);
 await click('禁用',`document.querySelector('.selection-bar')`);
 await until(`!!document.querySelector('ndr-picker')`);await click('确认保存',`document.querySelector('ndr-picker')`);
 await until(`!document.querySelector('ndr-picker')`);await ruleTab('禁用策略');
 await until(`document.querySelector('ndr-rules tbody')?.textContent.includes('snort-builtin-129-stream_tcp')`);
 await evaluate(`document.querySelector('ndr-rules tbody input').click()`);await click('删除',`document.querySelector('.selection-bar')`);
 await until(`!!document.querySelector('dialog .danger-button')`);await click('确认');
 await until(`document.querySelector('ndr-rules tbody')?.textContent.includes('暂无')`);
 await ruleTab('规则分组');await set('ndr-rules input[type="search"]','stream_tcp');
 await until(`document.querySelector('ndr-rules tbody')?.textContent.includes('TCP 流检查')`);
 await evaluate(`document.querySelector('ndr-rules tbody input').click()`);
 await click('抑制告警',`document.querySelector('.selection-bar')`);
 await until(`!!document.querySelector('ndr-picker')`);await click('确认保存',`document.querySelector('ndr-picker')`);
 await until(`!document.querySelector('ndr-picker')&&!!document.querySelector('.pending-rules')`);
 await ruleTab('告警抑制');
 await until(`document.querySelectorAll('ndr-rules tbody tr').length===1`);
 assert.equal(await evaluate(`document.querySelector('ndr-rules tbody .badge').textContent.trim()`),'整组策略');
 assert.equal(await evaluate(`document.querySelector('ndr-rules tbody tr').querySelectorAll('td')[5].textContent.trim()`),'2');
 assert.equal(await evaluate(`[...document.querySelectorAll('ndr-rules button')].some(b=>b.textContent.trim()==='整组移除')`),false);
 await evaluate(`document.querySelector('ndr-rules tbody input').click()`);await click('删除',`document.querySelector('.selection-bar')`);
 await click('确认',`document.querySelector('dialog')`);
 await until(`document.querySelector('ndr-rules tbody')?.textContent.includes('暂无')`);
 await ruleTab('规则源');
 await click('＋ 添加规则源');await until(`!!document.querySelector('ndr-source-editor')`);
 await set('input[name="slug"]','company');await set('input[name="label"]','Company rules');await set('input[name="url"]','https://example.test/rules?secret=fixture');await set('input[name="token"]','fixture-bearer');
 await click('保存',`document.querySelector('ndr-source-editor')`);await until(`!document.querySelector('ndr-source-editor')&&document.querySelector('ndr-rules tbody')?.textContent.includes('custom/company')`);
 const sources=await api('/api/rules/sources');assert.ok(!JSON.stringify(sources).includes('fixture'),'secrets never leave source API');
 await evaluate(`[...document.querySelectorAll('ndr-rules tbody tr')].find(r=>r.textContent.includes('snort/registered')).click()`);
 await until(`!!document.querySelector('ndr-source-editor input[name="oinkcode"]')`);
 await set('input[name="oinkcode"]','a'.repeat(40));await click('保存',`document.querySelector('ndr-source-editor')`);
 await until(`!document.querySelector('ndr-source-editor')`);
 const official=await api('/api/rules/sources');assert.equal(official.sources.find(s=>s.name==='snort/registered').credential_configured,true);assert.ok(!JSON.stringify(official).includes('a'.repeat(40)));
 assert.equal(official.sources.find(s=>s.name==='snort/registered').registered_version,'auto');
 for(const source of ['snort/community','snort/registered','snort/lightspd']){
  await until(`!![...document.querySelectorAll('ndr-rules tbody tr')].find(r=>r.textContent.includes(${JSON.stringify(source)}))`);
  await evaluate(`[...document.querySelectorAll('ndr-rules tbody tr')].find(r=>r.textContent.includes(${JSON.stringify(source)})).querySelector('input').click()`);
  await click('启用',`document.querySelector('.selection-bar')`);
  await until(`document.querySelector('ndr-rules .table-scroll')?.getAttribute('aria-busy')==='false'&&[...document.querySelectorAll('ndr-rules tbody tr')].find(r=>r.textContent.includes(${JSON.stringify(source)}))?.textContent.includes('已启用')`);
  await until(`!document.querySelector('.selection-bar')`);
 }
 const enabled=(await api('/api/rules/sources')).sources.filter(s=>s.enabled).map(s=>s.name);
 for(const source of ['snort/community','snort/registered','snort/lightspd'])assert.ok(enabled.includes(source),source+' stays enabled');
 assert.equal(await evaluate(`[...document.querySelectorAll('ndr-rules button')].find(b=>b.textContent.trim()==='更新规则集 ↗').disabled`),false);
 const before=await api('/api/overview');assert.ok(before.security.total>0);
 await nav('system');await until(`!!document.querySelector('.database-card')`);await click('清空历史事件');
 await until(`!!document.querySelector('dialog .danger-button')`);await click('确认');
 await until(`document.querySelector('.toast')?.textContent.includes('历史事件已清空')`);
 const after=await api('/api/overview');assert.equal(after.security.total,0);assert.equal(after.events_total,0);
 await nav('overview');await until(`!!document.querySelector('ndr-overview ndr-chart')`);
 assert.equal(await evaluate(`document.querySelector('ndr-overview .error')?.textContent||''`),'');
 assert.deepEqual(exceptions,[]);
 console.log('PASS: builtin disable/suppress groups, independent official sources, hidden credentials and dashboard after clearing history');
} finally {
 if(ws)ws.close();chrome.kill();await pause(500);
 const resolved=path.resolve(profile);
 assert.ok(path.dirname(resolved)===path.resolve(tmpdir())&&path.basename(resolved).startsWith('ndr-chrome-'));
 await rm(resolved,{recursive:true,force:true,maxRetries:5,retryDelay:200});
}
