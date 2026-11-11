// Rule management checks against the local Go preview started by preview.py.
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
 const pending=new Map(),exceptions=[],cancelled=new Set();
 let id=0,intercept=async p=>cdp('Fetch.continueRequest',{requestId:p.requestId});
 ws.onmessage=({data})=>{
  const message=JSON.parse(data);
  if(message.method==='Network.loadingFailed'&&message.params.canceled)cancelled.add(message.params.requestId);
  if(message.method==='Fetch.requestPaused')void intercept(message.params).catch(async e=>{if(e.message.includes('Invalid InterceptionId')&&message.params.networkId){for(let i=0;i<5;i++){if(cancelled.has(message.params.networkId))return;await pause(20);}}exceptions.push(e.message);});
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
 let job={state:'idle',rc:null,kind:'apply',lines:[]},scheduledRun=null,dirty=false,pendingSources=false,rulesFailed,actionFailure=false,sourceFailure=false;
 const writes=[];
 async function fulfill(p,data){return cdp('Fetch.fulfillRequest',{requestId:p.requestId,responseCode:200,responseHeaders:[{name:'Content-Type',value:'application/json'}],body:Buffer.from(JSON.stringify(data)).toString('base64')});}
 intercept=async p=>{
  const u=new URL(p.request.url),method=p.request.method;
  if(u.pathname==='/api/rules/page'&&method==='GET'){
   const cookies=(await cdp('Network.getCookies',{urls:[base]})).cookies;
   const page=await(await fetch(base+u.pathname+u.search,{headers:{Cookie:cookies.map(c=>c.name+'='+c.value).join('; ')}})).json();
   page.summary={...page.summary,rule_manager:true,pending:dirty,sources_pending:pendingSources,ruleset:{rules_loaded:125,rules_failed:rulesFailed},reload:{state:job.state==='running'?'running':'idle',ok:job.rc!==1}};
   if(u.searchParams.get('tab')==='disable')page.data=page.governance={disable:[{value:'sid:123'},{value:'sid:456'}],action:[],drop:[],suppress:[]};
   if(u.searchParams.get('tab')==='action')page.governance={drop:[],action:[{selector:'sid:123',action:'drop'},{selector:'sid:456',action:'drop'}]};
   if(u.searchParams.get('tab')==='sources'){
    page.data={sources:['first','second'].map(name=>({name,vendor:'fixture',enabled:true}))};
    page.schedule={...page.schedule,last_run:scheduledRun};
   }
   return fulfill(p,page);
  }
  if(u.pathname==='/api/rules'&&method==='GET')return fulfill(p,{rule_manager:true,pending:dirty,ruleset:{rules_loaded:125,rules_failed:rulesFailed},reload:{state:job.state==='running'?'running':'idle',ok:job.rc!==1},bans:[],local_rules:[]});
  if(u.pathname==='/api/rules/governance'&&method==='GET')return fulfill(p,{disable:[{value:'sid:123'},{value:'sid:456'}],action:[],drop:[],suppress:[]});
  if(u.pathname==='/api/actions/status')return fulfill(p,job);
  if(u.pathname==='/api/rules/action'&&method==='POST')return fulfill(p,actionFailure?{ok:true,errors:['sid:456（保存失败）']}:{ok:true});
  if(u.pathname==='/api/rules/source'&&method==='POST')return fulfill(p,sourceFailure&&JSON.parse(p.request.postData).name==='second'?{ok:false,message:'保存失败'}:{ok:true});
  if(method==='POST'&&['/api/rules/batch-delete','/api/actions/apply'].includes(u.pathname)){
   writes.push({path:u.pathname,body:JSON.parse(p.request.postData||'{}')});
   dirty=true;
   if(u.pathname==='/api/rules/batch-delete')return fulfill(p,{ok:true,pending:true});
   job={state:'running',rc:null,kind:'apply',started:Date.now()/1000,lines:['正在校验候选特征']};
   return fulfill(p,{ok:true});
  }
  return cdp('Fetch.continueRequest',{requestId:p.requestId});
 };
 await cdp('Fetch.enable',{patterns:[{urlPattern:'*/api/rules*'},{urlPattern:'*/api/actions/*'}]});
 const base=process.env.NDR_PREVIEW_URL||'http://127.0.0.1:19090';
 await cdp('Page.navigate',{url:base+'/login'});await until(`!!document.querySelector('#password')`);
 await set('#password','preview-only');await evaluate(`document.querySelector('form').submit()`);
 await until(`!!document.querySelector('[data-page="rules"]')`);await nav('rules');
 await until(`document.querySelector('.rule-engine-state')?.textContent.trim()==='引擎就绪'`);
 await click('操作日志',`document.querySelector('ndr-rules .tabs')`);
 await until(`document.querySelector('ndr-rules [role="tabpanel"]')?.textContent.includes('暂无手动操作日志')`);
 assert.equal(await evaluate(`!!document.querySelector('ndr-rules ndr-table')`),false);
 await ruleTab('阻断动作');await click('＋ 新建');
 await until(`!!document.querySelector('ndr-picker [aria-label="目标动作"]')`);
 const controls=await evaluate(`['选择对象类型','搜索候选特征','目标动作'].map(label=>{
  const {top,bottom}=document.querySelector('ndr-picker [aria-label="'+label+'"]').getBoundingClientRect();
  return {top,bottom};
 })`);
 for(const control of controls.slice(1)){
  assert.ok(Math.abs(control.top-controls[0].top)<1&&Math.abs(control.bottom-controls[0].bottom)<1,'picker controls should share the same row');
 }
 await click('取消',`document.querySelector('ndr-picker dialog')`);await until(`!document.querySelector('ndr-picker')`);
 await evaluate(`document.querySelector('ndr-rules thead input').click()`);await click('改为 reject');
 await until(`!document.querySelector('ndr-rules .selection-bar')`);
 await evaluate(`document.querySelector('ndr-rules thead input').click()`);await click('改为 drop');
 await until(`!document.querySelector('ndr-rules .selection-bar')`);
 actionFailure=true;await evaluate(`document.querySelector('ndr-rules thead input').click()`);await click('改为 reject');
 await until(`document.querySelector('.selection-bar')?.textContent.includes('已选 1')&&document.querySelector('ndr-rules .table-scroll').getAttribute('aria-busy')==='false'`);
 assert.equal(await evaluate(`document.querySelector('ndr-rules input[aria-label="选择 sid:456"]').checked`),true);
 actionFailure=false;await click('改为 drop');await until(`!document.querySelector('.selection-bar')`);
 await ruleTab('特征来源');await evaluate(`document.querySelector('ndr-rules thead input').click()`);await click('停用',`document.querySelector('.selection-bar')`);
 await until(`!document.querySelector('.selection-bar')`);
 sourceFailure=true;await evaluate(`document.querySelector('ndr-rules thead input').click()`);await click('启用',`document.querySelector('.selection-bar')`);
 await until(`document.querySelector('.selection-bar')?.textContent.includes('已选 1')&&document.querySelector('ndr-rules .table-scroll').getAttribute('aria-busy')==='false'`);
 assert.equal(await evaluate(`document.querySelector('ndr-rules input[aria-label="选择 second"]').checked`),true);
 sourceFailure=false;await click('启用',`document.querySelector('.selection-bar')`);await until(`!document.querySelector('.selection-bar')`);
 await ruleTab('禁用策略');await until(`document.querySelectorAll('ndr-rules tbody input').length===2`);
 await evaluate(`document.querySelectorAll('ndr-rules tbody input').forEach(e=>e.click())`);
 await click('删除');await click('确认',`document.querySelector('dialog')`);
 await until(`!!document.querySelector('.pending-rules')`);
 assert.equal(writes.length,1);assert.equal(writes[0].path,'/api/rules/batch-delete');
 assert.deepEqual(writes[0].body.paths.sort(),['/api/rules/disable/sid%3A123','/api/rules/disable/sid%3A456']);
 assert.equal(job.state,'idle','deleting configuration must not run a rule job');
 await click('应用更改 →');await until(`document.querySelector('.job-log')?.textContent.includes('正在校验候选特征')`);
 assert.equal(await evaluate(`document.querySelector('ndr-rules [role="tab"][aria-selected="true"]').textContent.trim()`),'操作日志');
 assert.equal(await evaluate(`[...document.querySelectorAll('ndr-rules button')].find(b=>b.textContent.trim()==='应用更改 →').disabled`),true);
 job={...job,state:'done',rc:1,finished:Date.now()/1000,lines:['校验失败，已恢复原特征']};
 await until(`document.querySelector('.job-log')?.textContent.includes('校验失败')`);
 await until(`document.querySelector('ndr-rules')?.textContent.includes('上次应用失败')`);
 await click('应用更改 →');await until(`document.querySelector('.job-log')?.textContent.includes('正在校验')`);
 scheduledRun={state:'done',rc:0,started:1,lines:['定时更新输出']};
 await ruleTab('特征来源');
 assert.equal(await evaluate(`!!document.querySelector('ndr-rules .job-log')||document.querySelector('ndr-rules').textContent.includes('定时更新输出')`),false);
 assert.equal(await evaluate(`[...document.querySelectorAll('ndr-rules button')].find(b=>b.textContent.trim()==='更新特征集 ↗').disabled`),true);
 job={...job,state:'done',rc:0,finished:Date.now()/1000,lines:['特征已校验并完成热重载']};
 dirty=false;
 await until(`!document.querySelector('.pending-rules')`);
 assert.equal(await evaluate(`!!document.querySelector('ndr-rules .job-log')`),false);
 await click('操作日志',`document.querySelector('ndr-rules .tabs')`);
 await until(`document.querySelector('.job-log[aria-label="特征操作日志输出"]')?.textContent.includes('完成热重载')&&document.querySelector('.job-log[aria-label="最近定时更新输出"]')?.textContent.includes('定时更新输出')`);
 assert.equal(writes.length,3);
 pendingSources=true;
 await ruleTab('特征来源');await until(`!!document.querySelector('.schedule-form')`);
 assert.equal(await evaluate(`[...document.querySelectorAll('ndr-rules button')].find(b=>b.textContent.trim()==='更新特征集 ↗').disabled`),false,'pending source selection must remain downloadable');
 await until(`document.querySelector('ndr-rules')?.textContent.includes('“应用更改”仅使用本地特征')`);
 await set('input[name="time"]','06:23');await click('保存计划');
 await until(`!document.querySelector('.schedule-form fieldset').disabled`);
 assert.equal((await api('/api/rules/schedule')).time,'06:23');
 await nav('overview');await nav('rules');await ruleTab('特征来源');
 await until(`document.querySelector('input[name="time"]')?.value==='06:23'`);
 await click('操作日志',`document.querySelector('ndr-rules .tabs')`);
 await until(`document.querySelector('.job-log')?.textContent.includes('完成热重载')`);
 assert.deepEqual(exceptions,[]);
 console.log('PASS: dedicated live and scheduled job logs; block action picker alignment; rule and source selections; explicit apply, draft deletion and schedule persistence');
} finally {
 if(ws)ws.close();chrome.kill();await pause(500);
 const resolved=path.resolve(profile);
 assert.ok(path.dirname(resolved)===path.resolve(tmpdir())&&path.basename(resolved).startsWith('ndr-chrome-'));
 await rm(resolved,{recursive:true,force:true,maxRetries:5,retryDelay:200});
}
