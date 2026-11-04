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
 await until(`!!document.querySelector('[data-page="drops"]')`);
 await nav('drops');
 for(const [i,key] of ['reasons','sources','destinations'].entries()){
  if(i)await nav('drops');
  await until(`document.querySelectorAll('ndr-events .three-grid ndr-table')[${i}]?.querySelector('tbody tr.clickable')`);
  const target=`document.querySelectorAll('ndr-events .three-grid ndr-table')[${i}].querySelector('tbody tr.clickable')`;
  const value=await evaluate(`(${target}).querySelector('td').textContent.trim()`);
  await evaluate(i===1?`(()=>{const e=${target};e.focus();e.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true}));})()`:`(${target}).click()`);
  await until(`location.hash==='#hunt'&&!!document.querySelector('ndr-hunt-query input')`);
  const q=await evaluate(`document.querySelector('ndr-hunt-query input').value`),field=key==='reasons'?'reason':key==='sources'?'src':'dst';
  assert.ok(q.includes('type: drop')&&q.includes(field+': '+JSON.stringify(value)),q);
  await until(`!!document.querySelector('ndr-events tbody tr.clickable')`);
 }
 await nav('rules');await ruleTab('阻断动作');
 await row('ndr-rules>section ndr-table','sid:9900200',true);
 await until(`document.querySelector('ndr-rule-collection')?.textContent.includes('Custom boundary fixture')`);await boundary();
 await row('ndr-rule-collection ndr-table','9900200');
 await until(`document.querySelector('ndr-details')?.textContent.includes('Custom boundary fixture')`);
 await close("document.querySelector('ndr-details')");
 assert.equal(await evaluate(`!!document.querySelector('ndr-rule-collection dialog[open]')`),true);
 await close("document.querySelector('ndr-rule-collection')");
 for(const text of ['msg:Custom*','group:emerging-*','re:sid:990020']){
  await row('ndr-rules>section ndr-table',text);await until(`document.querySelector('ndr-rule-collection tbody tr.clickable')`);
  await close("document.querySelector('ndr-rule-collection')");
 }
 await ruleTab('告警抑制');await row('ndr-rules>section ndr-table','9900200');
 await until(`document.querySelector('ndr-rule-collection')?.textContent.includes('Custom boundary fixture')`);
 await close("document.querySelector('ndr-rule-collection')");
 await row('ndr-rules>section ndr-table','9999999');
 await until(`document.querySelector('ndr-rule-collection .empty')?.textContent.includes('当前目录未找到')`);
 await close("document.querySelector('ndr-rule-collection')");
 await ruleTab('封禁对象');await row('ndr-rules>section ndr-table','example.org');
 await until(`document.querySelector('ndr-rule-collection .pager')?.textContent.includes('4 条')`);
 await click('调查相关事件 ↗',`document.querySelector('ndr-rule-collection')`);await until(`location.hash==='#hunt'`);
 assert.ok((await evaluate(`document.querySelector('ndr-hunt-query input').value`)).includes('dns: "example.org"'));
 await nav('rules');
 for(const tab of ['禁用策略','阻断动作','告警抑制']){
  await ruleTab(tab);await click('＋ 新建',`document.querySelector('ndr-rules')`);
  await until(`document.querySelectorAll('ndr-picker tbody tr').length>10`);
  assert.equal((await boundary()).scrollable,true);
  assert.equal(await evaluate(`getComputedStyle(document.querySelector('ndr-picker .modal-scroll'),'::-webkit-scrollbar-button').display`),'none');
  if(tab==='告警抑制')await snapshot();
  await close("document.querySelector('ndr-picker')");
 }
 await ruleTab('手动规则');await row('ndr-rules>section ndr-table','9900200');
 await until(`document.querySelector('ndr-details')?.textContent.includes('Custom boundary fixture')`);await close("document.querySelector('ndr-details')");
 await click('＋ 手动规则',`document.querySelector('ndr-rules')`);await until(`!!document.querySelector('ndr-rule-editor dialog')`);
 assert.equal((await boundary()).scrollable,true);
 await evaluate(`document.querySelector('ndr-rule-editor .modal-scroll').scrollTop=100000`);
 assert.ok(await evaluate(`document.querySelector('ndr-rule-editor .modal-scroll').scrollTop>0`));
 await snapshot('-manual');
 await close("document.querySelector('ndr-rule-editor')");
 await ruleTab('阻断动作');
 await evaluate(`document.querySelector('ndr-rules tbody input[aria-label="选择 sid:9900200"]').click()`);
 await click('改为 drop',`document.querySelector('ndr-rules')`);
 await until(`!!document.querySelector('.pending-rules')`);
 assert.equal(await evaluate(`fetch('/api/actions/status').then(r=>r.json()).then(d=>d.state)`),'idle','editing never runs a rule job');
 await ruleTab('规则源');await click('更新规则集 ↗',`document.querySelector('ndr-rules')`);
 await until(`document.querySelector('.job-log')?.textContent.includes('完成热重载')`);
 assert.equal(await evaluate(`fetch('/api/rules').then(r=>r.json()).then(d=>d.pending)`),true,'updates retain unconfirmed manual edits');
 await click('应用更改 →',`document.querySelector('ndr-rules')`);
 await until(`!document.querySelector('.pending-rules')`);
 assert.equal(await evaluate(`fetch('/api/rules').then(r=>r.json()).then(d=>d.pending)`),false);
 await nav('hunt');await until(`!!document.querySelector('ndr-hunt-query input')`);
 await set('ndr-hunt-query input','');await evaluate(`document.querySelector('ndr-hunt-query input').focus()`);
 await until(`!!document.querySelector('.query-option-scroll')`);
 assert.equal(await evaluate(`getComputedStyle(document.querySelector('.query-options')).overflowY`),'hidden');
 assert.equal(await evaluate(`getComputedStyle(document.querySelector('.query-option-scroll')).overflowY`),'auto');
 assert.deepEqual(exceptions,[]);
 console.log('PASS: drop shortcuts, custom and selector details, rounded scroll boundaries, pending edits, update isolation and explicit application');
}catch(error){await snapshot?.();throw error;}finally{
 if(ws)ws.close();chrome.kill();await pause(500);
 const resolved=path.resolve(profile);assert.ok(path.dirname(resolved)===path.resolve(tmpdir())&&path.basename(resolved).startsWith('ndr-chrome-'));
 await rm(resolved,{recursive:true,force:true,maxRetries:5,retryDelay:200});
}
