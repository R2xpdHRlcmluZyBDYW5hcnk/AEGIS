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
 async function summarize(){await until(`!!document.querySelector('.local-assistant .ai-body>.toolbar>button:not(:disabled)')`);await evaluate(`document.querySelector('.local-assistant .ai-body>.toolbar>button').click()`);}
 async function openIncident(generate=true){await until(`document.querySelector('ndr-events ndr-table tbody tr')?.textContent.includes('Suspicious')`);await evaluate(`document.querySelector('ndr-events ndr-table tbody tr').click()`);await until(`!!document.querySelector('.incident-heading')`);if(generate)await summarize();}
 async function close(){await evaluate(`document.querySelector('ndr-details [aria-label="关闭"]').click()`);await until(`!document.querySelector('ndr-details dialog')`);}
 async function waitCalls(count){for(let i=0;i<50;i++){if((await status()).calls>=count)return;await pause(100);}throw Error('Expected model request '+count);}
 async function waitCancelled(count){for(let i=0;i<30;i++){if((await status()).cancellations>=count)return;await pause(100);}throw Error('Upstream inference did not stop');}
 await cdp('Runtime.enable');await cdp('Page.enable');await cdp('Emulation.setDeviceMetricsOverride',{width:1440,height:1100,deviceScaleFactor:1,mobile:false});
 await cdp('Page.navigate',{url:'http://127.0.0.1:19090/login'});await until(`!!document.querySelector('#password')`);
 await evaluate(`document.querySelector('#password').value='preview-only';document.querySelector('form').submit()`);
 await until(`!!document.querySelector('[data-page="alerts"]')`);
 assert.equal((await status()).calls,0,'opening the dashboard does not invoke the model');
 await evaluate(`document.querySelector('[data-page="alerts"]').click()`);await openIncident(false);
 await pause(350);assert.equal((await status()).calls,0,'opening incident does not invoke inference');await summarize();
 await until(`document.querySelector('.ai-summary:not(.ai-draft)')?.textContent.includes('尚不能确认')`);
 assert.deepEqual((await status()).stages,['hunt','summary'],'the summary button plans searches and generates a summary');
 assert.equal(await evaluate(`!!document.querySelector('.ai-rule pre')`),false,'opening incident does not generate a rule');
 assert.equal((await api('/api/hunt/rules')).rules.length,0,'generation does not save rules');
 assert.ok(await evaluate(`document.querySelector('.ai-summary:not(.ai-draft)').textContent.includes('7 条会话记录')`));
 await evaluate(`document.querySelector('.ai-summary:not(.ai-draft) .ai-hunts').open=true`);await until(`!!document.querySelector('.ai-summary:not(.ai-draft) .ai-hunts pre')`);
 assert.ok(await evaluate(`document.querySelector('.ai-summary:not(.ai-draft) .ai-hunts pre').textContent.startsWith('(proto:TCP AND dport:443)')`));
 if(process.env.NDR_TEST_SCREENSHOT){const shot=await cdp('Page.captureScreenshot',{format:'png'});await writeFile(process.env.NDR_TEST_SCREENSHOT,Buffer.from(shot.data,'base64'));}
 await click('生成规则建议');await until(`!!document.querySelector('.ai-rule pre')`);
 assert.equal((await status()).stages.at(-1),'rule','rule generation requires its own click');
 await click('添加并应用规则');await until(`document.querySelector('.ai-rule')?.textContent.includes('已通过校验并应用')`);
 assert.equal((await api('/api/hunt/rules')).rules.length,1);
 await click('查看命中日志 ↗',`document.querySelector('.ai-summary:not(.ai-draft) .ai-hunts')`);await until(`location.hash==='#hunt'&&!document.querySelector('ndr-details dialog')`);
 await until(`document.querySelector('ndr-hunt-query input')?.value.includes('session_id:')`);
 assert.ok(await evaluate(`document.querySelector('ndr-hunt-query input').value.includes('NOT session_id:')`));
 await until(`document.querySelector('ndr-events tbody')?.textContent.includes('unalerted.example.test')`);
 await evaluate(`location.hash='#alerts'`);await openIncident();await until(`!!document.querySelector('.ai-summary:not(.ai-draft)')`);
 assert.equal(await evaluate(`!!document.querySelector('.ai-rule pre')`),false,'the summary action does not generate a rule');await close();
 await api('/__test/ai-plan',{mode:'natural'});await openIncident();await until(`document.querySelector('.ai-summary:not(.ai-draft)')?.textContent.includes('本次总结依据当前证据')`);
 assert.equal(await evaluate(`!!document.querySelector('.ai-summary:not(.ai-draft) .ai-hunts')`),false,'invalid planner output never executes a fixed fallback search');
 await close();await api('/__test/ai-plan',{mode:'default'});
 // Pause separately during reasoning, analysis notes and the summary body.
 await api('/__test/ai-stall',{reasoning:true,analysis:true,prefix:true});await openIncident();
 await until(`document.querySelector('.ai-thought')?.textContent==='先观察连接方向'`);
 assert.ok(await evaluate(`(()=>{
  const output=document.querySelector('.ai-output'),toolbar=output?.previousElementSibling;
  return output?.contains(document.querySelector('.ai-thought'))&&toolbar?.matches('.toolbar')
   &&getComputedStyle(output).borderTopStyle==='solid'
   &&output.getBoundingClientRect().top-toolbar.getBoundingClientRect().bottom>=12;
 })()`),'the live output has a border and space below the controls');
 assert.equal(await evaluate(`!!document.querySelector('.ai-note, .ai-draft')`),false,'reasoning reaches the browser before the other channels');
 await api('/__test/ai-stall',{analysis:true,prefix:true});
 await until(`document.querySelector('.ai-note')?.textContent==='先比对目标端口'`);
 assert.equal(await evaluate(`document.querySelector('.ai-thought').textContent`),'先观察连接方向并核对 <i>参考连接</i>。');
 assert.equal(await evaluate(`!!document.querySelector('.ai-thought i')`),false,'model text is rendered without interpreting markup');
 assert.equal(await evaluate(`document.querySelector('.ai-process').open`),true,'public analysis appears while the provider is still sending it');
 assert.equal(await evaluate(`!!document.querySelector('.ai-process ol, .ai-process .badge, .ai-draft')`),false,'the live note appears as plain text before the body');
 await api('/__test/ai-stall',{prefix:true});
 await until(`!!document.querySelector('.ai-draft p')?.textContent`);
 assert.ok(await evaluate(`!!document.querySelector('.ai-output .ai-process')&&!!document.querySelector('.ai-output .ai-draft')`),'analysis and streamed text share the output panel');
 assert.equal(await evaluate(`document.querySelector('.ai-note').textContent`),'先比对目标端口与附近会话。');
 assert.equal(await evaluate(`document.querySelector('.ai-process').open`),false,'process folds when public text starts');
 assert.equal(await evaluate(`!!document.querySelector('.ai-summary:not(.ai-draft)')`),false,'partial text appears before completion');
 assert.equal(await evaluate(`document.querySelector('.ai-draft').textContent.includes('先观察连接方向')`),false,'reasoning stays separate from the summary');
 await evaluate(`document.querySelector('.ai-process').open=true`);await pause(150);
 await api('/__test/ai-stall',{stall:false,prefix:false});await until(`!!document.querySelector('.ai-summary:not(.ai-draft)')`);
 assert.equal(await evaluate(`document.querySelector('.ai-process').open`),true,'manual reopening survives final output');
 assert.equal(await evaluate(`document.querySelector('.ai-summary:not(.ai-draft)').tagName`),'DIV','the body is not a collapsible section');
 await close();const streamedBefore=await status();await api('/__test/ai-stall',{stall:false,prefix:true});await openIncident();
 await until(`!!document.querySelector('.ai-draft p')?.textContent`);await close();await waitCancelled(streamedBefore.cancellations+1);
 await api('/__test/ai-stall',{stall:false,prefix:false});
 // All detail entry points require an explicit summary or rule action.
 async function openEvent(generate=true){
  await evaluate(`location.hash='#hunt'`);await until(`!!document.querySelector('ndr-hunt-query input')`);
  await evaluate(`(()=>{const e=document.querySelector('ndr-hunt-query input');e.value='';e.dispatchEvent(new Event('input',{bubbles:true}));document.querySelector('ndr-events form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}));})()`);
  await until(`document.querySelector('ndr-events ndr-table tbody tr')?.textContent.includes('Suspicious')&&document.querySelector('ndr-events .table-scroll')?.getAttribute('aria-busy')==='false'`);
  await evaluate(`document.querySelector('ndr-events ndr-table tbody tr').click()`);await until(`!!document.querySelector('.evidence-heading')`);if(generate)await summarize();
 }
 async function cancelCase(stage,action='close',event=false){
  await api('/__test/ai-stall',{stall:true,stage});const before=await status();
  if(event)await openEvent();else{await evaluate(`location.hash='#alerts'`);await openIncident();}
  await waitCalls(before.calls+(stage==='summary'?2:1));
  if(action==='escape'){
   await cdp('Input.dispatchKeyEvent',{type:'keyDown',key:'Escape',code:'Escape',windowsVirtualKeyCode:27});
   await cdp('Input.dispatchKeyEvent',{type:'keyUp',key:'Escape',code:'Escape',windowsVirtualKeyCode:27});
  }else if(action==='navigate')await evaluate(`location.hash='#hunt'`);
  else if(action==='unload'){
   await cdp('Page.navigate',{url:'about:blank'});await pause(350);await cdp('Page.navigate',{url:'http://127.0.0.1:19090/'});await until(`!!document.querySelector('[data-page="alerts"]')`);
  }else await close();
  await waitCancelled(before.cancellations+1);
 }
 await cancelCase('hunt');await cancelCase('summary','escape');await cancelCase('hunt','navigate');await cancelCase('hunt','close',true);
 await api('/__test/ai-stall',{stall:false});let before=await status();await openEvent(false);await pause(350);assert.equal((await status()).calls,before.calls,'hunting detail does not invoke inference');await summarize();
 await until(`document.querySelector('.ai-summary:not(.ai-draft)')?.textContent.includes('尚不能确认')`);assert.ok((await status()).calls>=before.calls+2,'the hunting detail summary button invokes inference');
 assert.ok(await evaluate(`[...document.querySelectorAll('.local-assistant button')].some(b=>b.textContent.trim()==='生成规则建议'&&!b.disabled)`),'ordinary logs also expose rule generation');
 await until(`document.querySelectorAll('#session-evidence tbody tr').length>=2`);
 assert.equal(await evaluate(`document.querySelector('.session-evidence h3').textContent.trim()`),'会话');
 assert.ok(await evaluate(`(()=>{const card=document.querySelector('.local-assistant'),header=card.querySelector(':scope>.section-heading'),reference=document.querySelector('.session-evidence'),other=reference.querySelector('.section-heading'),style=getComputedStyle(header),standard=getComputedStyle(other);return Math.abs(header.getBoundingClientRect().width-card.clientWidth)<1&&style.backgroundColor===standard.backgroundColor&&style.paddingTop===standard.paddingTop&&getComputedStyle(card).borderColor===getComputedStyle(reference).borderColor&&Math.abs(header.getBoundingClientRect().height-other.getBoundingClientRect().height)<1;})()`),'assistant header uses the evidence card style');
 assert.ok(await evaluate(`(()=>{const card=document.querySelector('.session-evidence'),next=[...document.querySelectorAll('.evidence-group')].find(e=>e!==card&&e.getBoundingClientRect().top>=card.getBoundingClientRect().bottom);return next&&next.getBoundingClientRect().top-card.getBoundingClientRect().bottom>=16;})()`),'evidence cards keep their spacing');
 await click('刷新',`document.querySelector('.session-evidence')`);await until(`!document.querySelector('.session-evidence button').disabled`);
 const nestedBefore=await status();await evaluate(`document.querySelector('#session-evidence tbody tr').click()`);await until(`!!document.querySelector('.evidence-heading')&&!document.querySelector('#session-evidence')`);
 await pause(250);assert.equal((await status()).calls,nestedBefore.calls,'nested logs do not start inference');await summarize();await until(`!!document.querySelector('.ai-summary:not(.ai-draft)')`);const backBefore=await status();await click('← 返回上一层');await until(`document.querySelectorAll('#session-evidence tbody tr').length>=2&&!!document.querySelector('.ai-summary:not(.ai-draft)')`);await pause(250);assert.equal((await status()).calls,backBefore.calls,'returning to previous details does not restart inference');
 await click('生成规则建议');await until(`!!document.querySelector('.ai-rule pre')`);
 assert.ok(await evaluate(`document.querySelector('.ai-rule pre').textContent.includes('any any -> any')`),'rule generation uses content rather than fixed endpoint pairs');
 await evaluate(`(()=>{const select=document.querySelector('select[aria-label="规则动作"]');select.value='block';select.dispatchEvent(new Event('change',{bubbles:true}));})()`);
 await until(`!document.querySelector('.ai-rule pre')`);await click('生成规则建议');await until(`document.querySelector('.ai-rule pre')?.textContent.startsWith('block ')`);
 assert.equal((await api('/api/hunt/rules')).rules.length,1,'ordinary rule suggestions are not written automatically');
 if(process.env.NDR_SESSION_SCREENSHOT){const shot=await cdp('Page.captureScreenshot',{format:'png'});await writeFile(process.env.NDR_SESSION_SCREENSHOT,Buffer.from(shot.data,'base64'));}
 await close();await api('/__test/ai-stall',{stall:true,stage:'summary'});before=await status();
 await evaluate(`location.hash='#alerts'`);await openIncident();await waitCalls(before.calls+2);
 const hidden=await cdp('Target.createTarget',{url:'about:blank'});await cdp('Target.activateTarget',{targetId:hidden.targetId});await until(`document.hidden`);await pause(500);
 assert.equal((await status()).cancellations,before.cancellations,'blur and hidden tabs keep inference running');
 await api('/__test/ai-stall',{stall:false});await until(`!!document.querySelector('.ai-summary:not(.ai-draft)')`);assert.equal((await status()).calls,before.calls+2);
 await cdp('Target.activateTarget',{targetId:tab.id});await cdp('Target.closeTarget',{targetId:hidden.targetId});await close();
 await cancelCase('summary','unload');
 assert.equal((await api('/api/hunt/rules')).rules.length,1,'cancelled requests never write manual rules');
 assert.deepEqual(exceptions,[]);
 await api('/__test/ai-stall',{stall:false});
 console.log('PASS: manual deep-thinking summaries, live text and auto-folding analysis summaries; autonomous related-event searches and feature-based rules; explicit writes; cancellation on close/navigation/unload and continuation on blur; consistent card headers');
}finally{
 if(ws)ws.close();chrome.kill();await pause(500);
 const resolved=path.resolve(profile);assert.ok(path.dirname(resolved)===path.resolve(tmpdir())&&path.basename(resolved).startsWith('ndr-chrome-'));
 await rm(resolved,{recursive:true,force:true,maxRetries:5,retryDelay:200});
}
