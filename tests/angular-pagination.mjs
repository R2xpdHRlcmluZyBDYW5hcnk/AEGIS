// Desktop regression with synthetic transport responses. Run via run_hunt_regression.py.
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
 const pending=new Map(),exceptions=[],streams=[];
 let id=0,intercept=async p=>cdp('Fetch.continueRequest',{requestId:p.requestId});
 ws.onmessage=({data})=>{
  const message=JSON.parse(data);
  if(message.method==='Fetch.requestPaused')void intercept(message.params).catch(e=>exceptions.push(e.message));
  if(message.method==='Network.requestWillBeSent'&&new URL(message.params.request.url).pathname==='/api/stream')streams.push(new URL(message.params.request.url).searchParams);
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
 async function nextPage(scope,endpoint,offsetKey='offset',fail=false){
  await until(`!!${scope}?.querySelector('.pager button:last-child:not(:disabled)')`);
  await evaluate(`(()=>{const t=${scope};t.querySelector('.table-scroll').scrollTop=99999;const m=t.closest('.modal-scroll')||document.querySelector('main');m.scrollTop=99999})()`);
  const before=await evaluate(`${scope}.querySelector('tbody tr').textContent`);
  const pager=await evaluate(`${scope}.querySelector('.pager').textContent`);
  let held;
  intercept=async p=>{
   const url=new URL(p.request.url);
   if(!held&&url.pathname===endpoint&&Number(url.searchParams.get(offsetKey))>0){held={id:p.requestId,url};return;}
   await cdp('Fetch.continueRequest',{requestId:p.requestId});
  };
  await click('下一页 →',scope);
  for(let i=0;i<50&&!held;i++)await pause(50);
  assert.ok(held,'a page request was held for '+endpoint);
  assert.equal(await evaluate(`${scope}.querySelector('.table-scroll').getAttribute('aria-busy')`),'true');
  assert.equal(await evaluate(`${scope}.querySelector('tbody tr').textContent`),before);
  assert.equal(await evaluate(`${scope}.querySelector('.pager').textContent`),pager);
  assert.ok(await evaluate(`[...${scope}.querySelectorAll('.pager button')].every(b=>b.disabled)`));
  if(['/api/hunt','/api/incidents','/api/events'].includes(endpoint)){
   assert.ok(held.url.searchParams.has('from')&&held.url.searchParams.has('to'),'history paging uses the displayed time range');
  }
  if(fail){
   await cdp('Fetch.fulfillRequest',{requestId:held.id,responseCode:503,responseHeaders:[{name:'Content-Type',value:'application/json'}],body:Buffer.from(JSON.stringify({error:'fixture page unavailable'})).toString('base64')});
   await until(`${scope}.querySelector('.table-scroll').getAttribute('aria-busy')==='false'&&document.body.textContent.includes('fixture page unavailable')`);
   assert.equal(await evaluate(`${scope}.querySelector('.pager').textContent`),pager);
   assert.equal(await evaluate(`${scope}.querySelector('tbody tr').textContent`),before);
   return;
  }
  await cdp('Fetch.continueRequest',{requestId:held.id});
  await until(`${scope}.querySelector('.table-scroll').getAttribute('aria-busy')==='false'&&${scope}.querySelector('tbody tr').textContent!==${JSON.stringify(before)}`);
  await pause(400);
  const position=await evaluate(`(()=>{const t=${scope},row=t.querySelector('tbody tr'),sc=t.querySelector('.table-scroll'),m=t.closest('.modal-scroll')||document.querySelector('main'),h=t.querySelector('thead').getBoundingClientRect().height,mh=m.querySelector(':scope > .modal-head')?.getBoundingClientRect().height||0;return {inner:row.getBoundingClientRect().top-sc.getBoundingClientRect().top-sc.clientTop-h,outer:row.getBoundingClientRect().top-m.getBoundingClientRect().top-m.clientTop-h-mh,main:document.querySelector('main').scrollTop}})()`);
  assert.ok(Math.abs(position.inner)<=3,JSON.stringify(position));
  assert.ok(position.outer>=-3&&position.outer<700,JSON.stringify(position));
 }
 await cdp('Fetch.enable',{patterns:[{urlPattern:'*/api/*'}]});
 await nav('overview');
 await until(`document.querySelectorAll('#recent tbody tr.clickable').length===10`);
 assert.equal(await evaluate(`!!document.querySelector('#recent .pager')`),false);
 assert.ok(await evaluate(`[...document.querySelectorAll('#recent tbody tr')].every(r=>r.cells[5].textContent.trim()==='TCP')`));
 const protocols=`[...document.querySelectorAll('ndr-overview section')].find(s=>s.querySelector('header h2')?.textContent==='连接传输协议')`;
 const udp=`[...(${protocols}?.querySelectorAll('ndr-table tbody tr')||[])].find(r=>r.cells[0].textContent.trim()==='UDP')`;
 await until(`!!(${protocols})`);
 await click('表格',protocols);
 await until(`!!(${udp})`);
 await evaluate(`(${udp}).click()`);
 await until(`document.querySelectorAll('#recent tbody tr.clickable').length===10&&[...document.querySelectorAll('#recent tbody tr')].every(r=>r.cells[5].textContent.trim()==='UDP')`);
 assert.equal(await evaluate(`!!document.querySelector('#recent .pager')`),false,'overview applies filters before selecting the ten rows');
 const events=`document.querySelector('ndr-events > section.card > ndr-table')`;
 async function search(input,value){await until(`!!document.querySelector(${JSON.stringify(input)})`);await set(input,value);await evaluate(`document.querySelector('ndr-events form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}))`);await until(`!!${events}?.querySelector('.pager button:last-child:not(:disabled)')`);}
 await nav('hunt');await search('ndr-hunt-query input','host:"paging.example.test"');
 await evaluate(`document.querySelector('ndr-events .filter-line input[type="checkbox"]').click()`);
 await until(`!${events}.querySelector('.pager button:last-child').disabled`);
 await nextPage(events,'/api/hunt','offset',true);
 await nextPage(events,'/api/hunt');
 assert.ok(await evaluate(`${events}.closest('section').textContent.includes('实时刷新已暂停')`));
 assert.ok(streams.filter(p=>p.get('topic')==='hunt').every(p=>Number(p.get('offset'))===0));
 const liveCount=streams.filter(p=>p.get('topic')==='hunt').length;
 await click('← 上一页',events);
 await until(`${events}.querySelector('.pager').textContent.includes('1 / 12')&&${events}.querySelector('.table-scroll').getAttribute('aria-busy')==='false'`);
 assert.ok(streams.filter(p=>p.get('topic')==='hunt').length>liveCount,'the first page resumes live refresh');
 await nav('alerts');await search('ndr-events input[type="search"]','Paging fixture');
 await nextPage(events,'/api/incidents');
 await click('← 上一页',events);
 await until(`${events}.querySelector('.pager').textContent.includes('1 / 2')&&${events}.querySelector('.table-scroll').getAttribute('aria-busy')==='false'`);
 await evaluate(`${events}.querySelector('tbody tr').click()`);
 await until(`!!document.querySelector('#incident-network .pager button:last-child:not(:disabled)')`);
 await nextPage(`document.querySelector('#incident-network')`,'/api/incident','network_offset');
 await evaluate(`document.querySelector('ndr-details [aria-label="关闭"]').click()`);
 await nav('drops');await search('ndr-events input[type="search"]','Paging fixture');
 await nextPage(events,'/api/events');
 await click('← 上一页',events);
 await until(`${events}.querySelector('.pager').textContent.includes('1 / 2')&&${events}.querySelector('.table-scroll').getAttribute('aria-busy')==='false'`);
 await evaluate(`${events}.querySelector('tbody tr').click()`);
 await until(`!!document.querySelector('#session-evidence .pager button:last-child:not(:disabled)')`);
 await nextPage(`document.querySelector('#session-evidence')`,'/api/session');
 await click('刷新',`document.querySelector('.session-evidence header')`);
 await until(`document.querySelector('#session-evidence .table-scroll').getAttribute('aria-busy')==='false'`);
 assert.ok(await evaluate(`document.querySelector('#session-evidence .pager').textContent.includes('2 / 2')`));
 await evaluate(`document.querySelector('ndr-details [aria-label="关闭"]').click()`);
 await nav('rules');await ruleTab('检测签名');
 await nextPage(`document.querySelector('ndr-rules ndr-table')`,'/api/rules/page');
 await ruleTab('规则分组');await set('ndr-rules input[type="search"]','emerging-scan');
 await until(`document.querySelector('ndr-rules tbody')?.textContent.includes('emerging-scan')`);
 await evaluate(`document.querySelector('ndr-rules tbody tr').click()`);await until(`!!document.querySelector('ndr-rule-collection tbody tr.clickable')`);
 await nextPage(`document.querySelector('ndr-rule-collection ndr-table')`,'/api/rules/selection');
 await evaluate(`document.querySelector('ndr-rule-collection [aria-label="关闭"]').click()`);await until(`!document.querySelector('ndr-rule-collection')`);
 await ruleTab('禁用策略');await click('＋ 新建',`document.querySelector('ndr-rules')`);await until(`!!document.querySelector('ndr-picker tbody tr')`);
 await nextPage(`document.querySelector('ndr-picker ndr-table')`,'/api/rules/search');
 assert.deepEqual(exceptions,[]);
 console.log('PASS: filtered recent logs, stable paging through delays and errors, live refresh and detail tables');
} finally {
 if(ws)ws.close();chrome.kill();await pause(500);
 const resolved=path.resolve(profile);
 assert.ok(path.dirname(resolved)===path.resolve(tmpdir())&&path.basename(resolved).startsWith('ndr-chrome-'));
 await rm(resolved,{recursive:true,force:true,maxRetries:5,retryDelay:200});
}
