// Local synthetic data only: navigation, reusable rule details and rounded scroll boundaries.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdtemp,readFile,rm,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
const profile=await mkdtemp(path.join(tmpdir(),'ndr-chrome-'));
const chrome=spawn(process.env.CHROME_PATH||'C:/Program Files/Google/Chrome/Application/chrome.exe',[
 '--headless=new','--disable-gpu','--no-first-run','--no-default-browser-check',
 '--remote-debugging-port=0','--remote-allow-origins=*',`--user-data-dir=${profile}`,'about:blank'
],{windowsHide:true,stdio:'ignore'});
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
let ws,snapshot;
try{
 let port;
 for(let i=0;i<100;i++){try{port=Number((await readFile(path.join(profile,'DevToolsActivePort'),'utf8')).split('\n')[0]);break;}catch{await pause(100);}}
 assert.ok(port,'Chrome starts');
 const tab=await(await fetch(`http://127.0.0.1:${port}/json/new?about:blank`,{method:'PUT'})).json();
 ws=new WebSocket(tab.webSocketDebuggerUrl);await new Promise((resolve,reject)=>{ws.onopen=resolve;ws.onerror=reject;});
 const pending=new Map(),exceptions=[];let id=0;
 ws.onmessage=({data})=>{const m=JSON.parse(data);if(m.method==='Runtime.exceptionThrown')exceptions.push(m.params.exceptionDetails);if(m.id&&pending.has(m.id)){const p=pending.get(m.id);pending.delete(m.id);m.error?p.reject(new Error(JSON.stringify(m.error))):p.resolve(m.result);}};
 function cdp(method,params={}){const sequence=++id;return new Promise((resolve,reject)=>{const timer=setTimeout(()=>{pending.delete(sequence);reject(new Error(method+' timed out'));},15000);pending.set(sequence,{resolve:v=>{clearTimeout(timer);resolve(v);},reject:e=>{clearTimeout(timer);reject(e);}});ws.send(JSON.stringify({id:sequence,method,params}));});}
 snapshot=async(suffix='')=>{if(process.env.NDR_SCREENSHOT){await pause(450);const {data}=await cdp('Page.captureScreenshot',{format:'png'});await writeFile(process.env.NDR_SCREENSHOT.replace('.png',suffix+'.png'),Buffer.from(data,'base64'));}};
 async function evaluate(expression){const r=await cdp('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});if(r.exceptionDetails)throw new Error(JSON.stringify(r.exceptionDetails));return r.result.value;}
 async function until(expression){for(let i=0;i<100;i++){if(await evaluate(`Boolean(${expression})`))return;await pause(100);}throw new Error('Timed out: '+expression+'\n'+await evaluate('document.body.innerText.slice(-3000)'));}
 async function click(text,scope='document'){const selector=`[...${scope}.querySelectorAll('button')].find(b=>b.textContent.trim()===${JSON.stringify(text)}&&!b.disabled)`;await until(`!!(${selector})`);await evaluate(`(${selector}).click()`);}
 async function set(selector,value){await evaluate(`(()=>{const e=document.querySelector(${JSON.stringify(selector)});e.value=${JSON.stringify(value)};e.dispatchEvent(new Event('input',{bubbles:true}));})()`);}
 async function nav(page){await evaluate(`document.querySelector('[data-page="${page}"]').click()`);await until(`location.hash==='#${page}'`);}
 async function ruleTab(title){await click(title,`document.querySelector('ndr-rules .tabs')`);await until(`document.querySelector('ndr-rules .tabs button.active')?.textContent.trim()===${JSON.stringify(title)}&&document.querySelector('ndr-rules ndr-table .table-scroll')?.getAttribute('aria-busy')==='false'`);}
 async function close(scope){await evaluate(`${scope}.querySelector('dialog[open] [aria-label="关闭"]').click()`);}
 async function row(table,text,keyboard=false){const selector=`[...document.querySelectorAll(${JSON.stringify(table+' tbody tr.clickable')})].find(e=>e.querySelector('input')?.getAttribute('aria-label')===${JSON.stringify('选择 '+text)}||e.textContent.includes(${JSON.stringify(text)}))`;await until(`!!(${selector})`);await evaluate(keyboard?`(()=>{const e=${selector};e.focus();e.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true}));})()`:`(${selector}).click()`);}
 async function boundary(){const r=await evaluate(`(()=>{const d=[...document.querySelectorAll('dialog[open]')].at(-1),s=d.querySelector('.modal-scroll'),a=d.getBoundingClientRect(),b=s.getBoundingClientRect();return {outer:getComputedStyle(d).overflowY,inner:getComputedStyle(s).overflowY,top:b.top-a.top,bottom:a.bottom-b.bottom,scrollable:s.scrollHeight>s.clientHeight};})()`);assert.equal(r.outer,'hidden');assert.equal(r.inner,'auto');assert.ok(r.top>=1&&r.bottom>=1);return r;}
 await cdp('Runtime.enable');await cdp('Page.enable');
 await cdp('Emulation.setDeviceMetricsOverride',{width:1440,height:1100,deviceScaleFactor:1,mobile:false});
 const base=process.env.NDR_PREVIEW_URL||'http://127.0.0.1:19090';
 await cdp('Page.navigate',{url:base+'/login'});await until(`!!document.querySelector('#password')`);
 await set('#password','preview-only');await evaluate(`document.querySelector('form').submit()`);

 await until(`!!document.querySelector('[data-page="rules"]')`);
 await nav('rules');await ruleTab('告警抑制');
 assert.equal(await evaluate(`[...document.querySelectorAll('ndr-rules .rule-summary button')].some(e=>e.textContent.trim()==='应用更改 →')`),true);
 assert.equal(await evaluate(`document.querySelector('ndr-rules').textContent.includes('应用规则')`),false);
 const api=async url=>evaluate(`fetch(${JSON.stringify(url)}).then(r=>r.json())`);
 const original=(await api('/api/rules/governance')).suppress.map(r=>r.sid);
 assert.equal(await evaluate(`[...document.querySelectorAll('ndr-rules button')].some(b=>b.textContent.trim()==='整组移除')`),false);
 for(let page=0;page<5;page++){
  await evaluate(`document.querySelector('ndr-rules thead input[aria-label="选择当前页"]').click()`);
  if(page<4)await click('下一页 →',`document.querySelector('ndr-rules>section ndr-table')`);
 }
 await until(`document.querySelector('.selection-bar')?.textContent.includes('已选 250')`);
 await click('删除',`document.querySelector('.selection-bar')`);await click('取消',`document.querySelector('dialog')`);
 assert.deepEqual((await api('/api/rules/governance')).suppress.map(r=>r.sid),original);
 await click('删除',`document.querySelector('.selection-bar')`);await click('确认',`document.querySelector('dialog')`);
 await until(`!!document.querySelector('.pending-rules')&&!document.querySelector('.selection-bar')`);
 const retained=original.slice(250);
 assert.deepEqual((await api('/api/rules/governance')).suppress.map(r=>r.sid),retained);
 async function addGroup(name){
  await click('＋ 新建');await until(`!!document.querySelector('ndr-picker')`);
  await evaluate(`(()=>{const e=document.querySelector('[aria-label="选择对象类型"]');e.value='group';e.dispatchEvent(new Event('change',{bubbles:true}));})()`);
  await set('ndr-picker input[type="search"]',name);await until(`document.querySelectorAll('ndr-picker tbody input').length===1`);
  await evaluate(`document.querySelector('ndr-picker tbody input').click()`);await click('确认保存',`document.querySelector('ndr-picker')`);
  await until(`!document.querySelector('ndr-picker')`);
 }
 for(const name of ['emerging-scan','overlap'])await addGroup(name);
 let gov=await api('/api/rules/governance');assert.equal(gov.suppress_groups.length,2);
 await set('ndr-rules input[type="search"]','emerging-scan');await until(`document.querySelectorAll('ndr-rules tbody input').length===1`);
 await evaluate(`document.querySelector('ndr-rules tbody input').click()`);
 await set('ndr-rules input[type="search"]','9999999');await until(`document.querySelectorAll('ndr-rules tbody input').length===1`);
 await evaluate(`document.querySelector('ndr-rules tbody input').click()`);
 await until(`document.querySelector('.selection-bar')?.textContent.includes('已选 2')`);
 await click('删除',`document.querySelector('.selection-bar')`);await click('确认',`document.querySelector('dialog')`);
 await until(`!document.querySelector('.selection-bar')`);
 gov=await api('/api/rules/governance');assert.deepEqual(gov.suppress.map(r=>r.sid),retained.filter(sid=>sid!==9999999));
 assert.deepEqual(gov.suppress_groups.map(r=>r.name),['overlap']);
 await set('ndr-rules input[type="search"]','');await until(`document.querySelectorAll('ndr-rules tbody input').length>0`);
 const pages=Math.ceil((gov.suppress.length+gov.suppress_groups.length)/50);
 for(let page=0;page<pages;page++){
  await evaluate(`document.querySelector('ndr-rules thead input[aria-label="选择当前页"]').click()`);
  if(page<pages-1)await click('下一页 →',`document.querySelector('ndr-rules>section ndr-table')`);
 }
 await click('删除',`document.querySelector('.selection-bar')`);await click('确认',`document.querySelector('dialog')`);
 await until(`document.querySelector('ndr-rules tbody')?.textContent.includes('暂无')`);
 gov=await api('/api/rules/governance');assert.equal(gov.suppress.length,0);assert.equal(gov.suppress_groups.length,0);
 assert.equal((await api('/api/actions/status')).state,'idle');
 await click('应用更改 →',`document.querySelector('ndr-rules')`);await until(`!document.querySelector('.pending-rules')`);
 assert.deepEqual(exceptions,[]);
 console.log('PASS: one deletion entry for groups and individual suppressions, cancellation, selection over 200, independent ownership, legacy pending entries, empty state and explicit apply');
}catch(error){await snapshot?.();throw error;}finally{
 if(ws)ws.close();chrome.kill();await pause(500);
 const resolved=path.resolve(profile);assert.ok(path.dirname(resolved)===path.resolve(tmpdir())&&path.basename(resolved).startsWith('ndr-chrome-'));
 await rm(resolved,{recursive:true,force:true,maxRetries:5,retryDelay:200});
}
