// Desktop integration against serve_preview.py and its cancellable synthetic model.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdtemp,readFile,rm,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
const profile=await mkdtemp(path.join(tmpdir(),'ndr-chrome-'));
const chrome=spawn(process.env.CHROME_PATH||'C:/Program Files/Google/Chrome/Application/chrome.exe',[
 '--headless=new','--disable-gpu','--no-first-run','--no-default-browser-check','--remote-debugging-port=0','--remote-allow-origins=*',`--user-data-dir=${profile}`,'about:blank'
],{windowsHide:true,stdio:'ignore'});
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
let ws;
try{
 let port;
 for(let i=0;i<100;i++){try{port=Number((await readFile(path.join(profile,'DevToolsActivePort'),'utf8')).split('\n')[0]);break;}catch{await pause(100);}}
 assert.ok(port,'Chrome starts');
 const tab=await(await fetch(`http://127.0.0.1:${port}/json/new?about:blank`,{method:'PUT'})).json();
 ws=new WebSocket(tab.webSocketDebuggerUrl);await new Promise((resolve,reject)=>{ws.onopen=resolve;ws.onerror=reject;});
 const pending=new Map(),exceptions=[];let id=0;
 ws.onmessage=({data})=>{const m=JSON.parse(data);if(m.method==='Runtime.exceptionThrown')exceptions.push(m.params.exceptionDetails);if(m.id&&pending.has(m.id)){const p=pending.get(m.id);pending.delete(m.id);m.error?p.reject(Error(JSON.stringify(m.error))):p.resolve(m.result);}};
 function cdp(method,params={}){const sequence=++id;return new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('CDP timeout '+method)),15000);pending.set(sequence,{resolve:v=>{clearTimeout(timer);resolve(v);},reject:e=>{clearTimeout(timer);reject(e);}});ws.send(JSON.stringify({id:sequence,method,params}));});}
 async function evaluate(expression){const r=await cdp('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});if(r.exceptionDetails)throw Error(JSON.stringify(r.exceptionDetails));return r.result.value;}
 async function until(expression){for(let i=0;i<100;i++){if(await evaluate(expression))return;await pause(100);}throw Error('Timed out: '+expression+'\n'+await evaluate('document.body.innerText.slice(-3500)'));}
 async function click(text,scope='document'){const selector=`[...${scope}.querySelectorAll('button')].find(b=>b.textContent.trim()===${JSON.stringify(text)}&&!b.disabled)`;await until(`!!(${selector})`);await evaluate(`(${selector}).click()`);}
 async function api(url,body){return evaluate(`fetch(${JSON.stringify(url)},${body===undefined?'{}':JSON.stringify({method:'POST',headers:{'Content-Type':'application/json','X-Requested-With':'ips-web'},body:JSON.stringify(body)})}).then(r=>r.json())`);}
 const status=()=>api('/__test/ai-status');
 async function openIncident(){await until(`document.querySelector('ndr-events ndr-table tbody tr')?.textContent.includes('Suspicious')`);await evaluate(`document.querySelector('ndr-events ndr-table tbody tr').click()`);await until(`!!document.querySelector('.incident-heading')`);}
 async function close(){await evaluate(`document.querySelector('ndr-details [aria-label="关闭"]').click()`);await until(`!document.querySelector('ndr-details dialog')`);}
 async function waitCalls(count){for(let i=0;i<50;i++){if((await status()).calls>=count)return;await pause(100);}throw Error('Expected model request '+count);}
 async function waitCancelled(count){for(let i=0;i<30;i++){if((await status()).cancellations>=count)return;await pause(100);}throw Error('Upstream inference did not stop');}
 await cdp('Runtime.enable');await cdp('Page.enable');await cdp('Emulation.setDeviceMetricsOverride',{width:1440,height:1100,deviceScaleFactor:1,mobile:false});
 await cdp('Page.navigate',{url:'http://127.0.0.1:19090/login'});await until(`!!document.querySelector('#password')`);
 await evaluate(`document.querySelector('#password').value='preview-only';document.querySelector('form').submit()`);
 await until(`!!document.querySelector('[data-page="alerts"]')`);
 assert.equal((await status()).calls,0,'opening the dashboard does not invoke the model');
 await evaluate(`document.querySelector('[data-page="alerts"]').click()`);await openIncident();
 await until(`document.querySelector('.ai-summary')?.textContent.includes('尚不能确认')`);
 assert.deepEqual((await status()).stages,['hunt','summary'],'opening incident plans searches and generates a summary');
 assert.equal(await evaluate(`!!document.querySelector('.ai-rule pre')`),false,'opening incident does not generate a rule');
 assert.equal((await api('/api/hunt/rules')).rules.length,0,'generation does not save rules');
 assert.ok(await evaluate(`document.querySelector('.ai-summary').textContent.includes('7 条会话记录')`));
 await evaluate(`document.querySelector('.ai-hunts').open=true`);await until(`!!document.querySelector('.ai-hunts pre')`);
 assert.ok(await evaluate(`document.querySelector('.ai-hunts pre').textContent.startsWith('session_id:')`));
 if(process.env.NDR_TEST_SCREENSHOT){const shot=await cdp('Page.captureScreenshot',{format:'png'});await writeFile(process.env.NDR_TEST_SCREENSHOT,Buffer.from(shot.data,'base64'));}
 await click('生成规则建议');await until(`!!document.querySelector('.ai-rule pre')`);
 assert.equal((await status()).stages.at(-1),'rule','rule generation requires its own click');
 await click('添加并应用规则');await until(`document.querySelector('.ai-rule')?.textContent.includes('已通过校验并应用')`);
 assert.equal((await api('/api/hunt/rules')).rules.length,1);
 await click('查看命中日志 ↗',`document.querySelector('.ai-hunts')`);await until(`location.hash==='#hunt'&&!document.querySelector('ndr-details dialog')`);
 await until(`document.querySelector('ndr-hunt-query input')?.value.includes('session_id:')`);
 assert.ok(await evaluate(`document.querySelector('ndr-hunt-query input').value.includes('type:alert')`));
 await evaluate(`location.hash='#alerts'`);await openIncident();await until(`!!document.querySelector('.ai-summary')`);
 assert.equal(await evaluate(`!!document.querySelector('.ai-rule pre')`),false,'reopening only refreshes summary');await close();
 await api('/__test/ai-plan',{mode:'natural'});await openIncident();await until(`document.querySelector('.ai-summary')?.textContent.includes('已使用基础核查条件')`);
 await evaluate(`document.querySelector('.ai-hunts').open=true`);
 assert.equal(await evaluate(`[...document.querySelectorAll('.ai-hunts pre')].some(e=>e.textContent.includes('检查'))`),false,'natural-language model replies are never rendered as executable searches');
 assert.equal(await evaluate(`document.querySelector('.ai-hunts').textContent.includes('校验失败')||document.querySelector('.ai-hunts').textContent.includes('检索未完成')`),false,'fallback checks execute successfully');
 await close();await api('/__test/ai-plan',{mode:'default'});
 // Cancel before the first token: close button, Escape, navigation and unload.
 await api('/__test/ai-stall',{stall:true});let calls=(await status()).calls,cancellations=(await status()).cancellations;
 await openIncident();await waitCalls(++calls);await close();await waitCancelled(++cancellations);
 await openIncident();await waitCalls(++calls);await cdp('Input.dispatchKeyEvent',{type:'keyDown',key:'Escape',code:'Escape',windowsVirtualKeyCode:27});await cdp('Input.dispatchKeyEvent',{type:'keyUp',key:'Escape',code:'Escape',windowsVirtualKeyCode:27});await waitCancelled(++cancellations);
 await api('/__test/ai-stall',{stall:true,stage:'summary'});await openIncident();calls+=2;await waitCalls(calls);await close();await waitCancelled(++cancellations);
 await openIncident();calls+=2;await waitCalls(calls);const hiddenTab=await cdp('Target.createTarget',{url:'about:blank'});await cdp('Target.activateTarget',{targetId:hiddenTab.targetId});await until(`document.hidden`);await pause(500);assert.equal((await status()).cancellations,cancellations,'switching browser tabs keeps inference running');await api('/__test/ai-stall',{stall:false});await until(`!!document.querySelector('.ai-summary')`);assert.equal((await status()).calls,calls,'hidden tab completes the same inference without restarting');await cdp('Target.activateTarget',{targetId:tab.id});await until(`!document.hidden`);await cdp('Target.closeTarget',{targetId:hiddenTab.targetId});await close();await api('/__test/ai-stall',{stall:true});
 await openIncident();await waitCalls(++calls);await evaluate(`location.hash='#hunt'`);await until(`!document.querySelector('ndr-details dialog')`);await waitCancelled(++cancellations);
 await until(`document.querySelector('ndr-events ndr-table tbody tr')?.textContent.includes('Suspicious')`);await evaluate(`document.querySelector('ndr-events ndr-table tbody tr').click()`);await until(`!!document.querySelector('.evidence-heading')`);
 assert.equal((await status()).calls,calls,'event evidence summary is generated only on click');
 await click('生成会话总结');await waitCalls(++calls);await close();await waitCancelled(++cancellations);
 await api('/__test/ai-stall',{stall:false});await evaluate(`document.querySelector('ndr-events ndr-table tbody tr').click()`);await until(`!!document.querySelector('.evidence-heading')`);await until(`document.querySelectorAll('#session-evidence tbody tr').length>=2`);await click('刷新',`document.querySelector('.session-evidence')`);assert.equal(await evaluate(`document.querySelector('.session-evidence h3').textContent.trim()`),'会话');assert.ok(await evaluate(`(()=>{const card=document.querySelector('.session-evidence'),next=[...document.querySelectorAll('.evidence-group')].find(e=>e!==card&&e.getBoundingClientRect().top>=card.getBoundingClientRect().bottom);return next&&next.getBoundingClientRect().top-card.getBoundingClientRect().bottom>=16;})()`),'session card has spacing before the next evidence card');await until(`!document.querySelector('.session-evidence button').disabled`);assert.ok(await evaluate(`(()=>{const session=document.querySelector('.session-evidence'),header=session.querySelector('.section-heading'),other=[...document.querySelectorAll('.evidence-group>h3')].find(e=>e.closest('.evidence-group')!==session),button=header.querySelector('button');if(!other)return false;const first=header.getBoundingClientRect(),second=other.getBoundingClientRect(),control=button.getBoundingClientRect(),style=getComputedStyle(header),reference=getComputedStyle(other);return Math.abs(first.height-second.height)<1&&style.borderBottomWidth===reference.borderBottomWidth&&style.paddingLeft===reference.paddingLeft&&control.top>=first.top&&control.bottom<=first.bottom;})()`),'session and evidence cards share title height, border and padding');const sessionRequestsBefore=await evaluate(`performance.getEntriesByType('resource').filter(e=>e.name.includes('/api/session?')).length`);await evaluate(`document.querySelector('#session-evidence tbody tr').click()`);await until(`!!document.querySelector('.raw-evidence')&&!document.querySelector('.detail-loading')`);assert.equal(await evaluate(`!!document.querySelector('.session-evidence')`),false,'nested log details omit the session table');assert.equal(await evaluate(`performance.getEntriesByType('resource').filter(e=>e.name.includes('/api/session?')).length`),sessionRequestsBefore,'nested log details do not reload the session');await click('← 返回上一层');await until(`document.querySelectorAll('#session-evidence tbody tr').length>=2`);if(process.env.NDR_SESSION_SCREENSHOT){await evaluate(`document.querySelector('.session-evidence').scrollIntoView({block:'start'});document.querySelector('ndr-details .modal-scroll').scrollTop-=100`);const shot=await cdp('Page.captureScreenshot',{format:'png'});await writeFile(process.env.NDR_SESSION_SCREENSHOT,Buffer.from(shot.data,'base64'));}await until(`document.querySelectorAll('#session-evidence tbody tr').length>=2`);await click('生成会话总结');await until(`document.querySelector('.ai-summary')?.textContent.includes('尚不能确认')`);calls+=2;await click('调查关联事件 ↗');await until(`!document.querySelector('ndr-details dialog')&&document.querySelector('ndr-range select')?.value==='all'`);assert.ok(await evaluate(`document.querySelector('.filter-line input[type=checkbox]').checked`),'session investigation follows late records');
 await api('/__test/ai-stall',{stall:true});await evaluate(`location.hash='#alerts'`);await openIncident();await waitCalls(++calls);await cdp('Page.navigate',{url:'about:blank'});await pause(350);await cdp('Page.navigate',{url:'http://127.0.0.1:19090/'});await until(`!!document.querySelector('[data-page="alerts"]')`);await waitCancelled(++cancellations);
 assert.equal((await api('/api/hunt/rules')).rules.length,1,'all cancelled requests leave manual rules unchanged');
 assert.deepEqual(exceptions,[]);
 await api('/__test/ai-stall',{stall:false});
 console.log('PASS: automatic session summary, real hunting queries and result navigation; rules require clicks; both model stages cancel on leaving and continue when tabs lose focus');
}finally{
 if(ws)ws.close();chrome.kill();await pause(500);
 const resolved=path.resolve(profile);assert.ok(path.dirname(resolved)===path.resolve(tmpdir())&&path.basename(resolved).startsWith('ndr-chrome-'));
 await rm(resolved,{recursive:true,force:true,maxRetries:5,retryDelay:200});
}
