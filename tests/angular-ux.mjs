import {testOutput} from './test-output.mjs';
// Dependency-free Chrome DevTools smoke test. Start serve_preview.py first.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, writeFile, mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
const baseUrl=process.env.NDR_PREVIEW_URL||'http://127.0.0.1:19090';
const profile = await mkdtemp(path.join(tmpdir(), 'ndr-chrome-'));
const chromePath = process.env.CHROME_PATH || 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const chrome = spawn(chromePath, ['--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check', '--remote-debugging-port=0', '--remote-allow-origins=*', `--user-data-dir=${profile}`, 'about:blank'], { windowsHide: true, stdio: 'ignore' });
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
let ws;
try {
  let port;
  for (let i = 0; i < 100; i++) {
    try { port = Number((await readFile(path.join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')[0]); break; }
    catch { await pause(100); }
  }
  assert.ok(port, 'Chrome starts');
  const tab = await (await fetch(`http://127.0.0.1:${port}/json/new?about:blank`, { method: 'PUT' })).json();
  ws = new WebSocket(tab.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; });
  const pending = new Map(), exceptions = [];
  let id = 0;
  let route = params => cdp('Fetch.continueRequest',{requestId:params.requestId});
  ws.onmessage = ({ data }) => {
    const message = JSON.parse(data);
    if(message.method==='Fetch.requestPaused')void route(message.params).catch(e=>exceptions.push(e.message));
    if (message.method === 'Runtime.exceptionThrown') exceptions.push(message.params.exceptionDetails);
    if (message.id && pending.has(message.id)) {
      const { resolve, reject } = pending.get(message.id); pending.delete(message.id);
      message.error ? reject(new Error(JSON.stringify(message.error))) : resolve(message.result);
    }
  };
  function cdp(method, params = {}) {
    const sequence = ++id;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { pending.delete(sequence); reject(new Error('CDP timeout: ' + method)); }, 15000);
      pending.set(sequence, { resolve: value => { clearTimeout(timer); resolve(value); }, reject: error => { clearTimeout(timer); reject(error); } });
      ws.send(JSON.stringify({ id: sequence, method, params }));
    });
  }
  async function evaluate(expression) {
    const result = await cdp('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
    if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
    return result.result.value;
  }
  async function execute(script) { return evaluate('(async () => {' + script + '\n})()'); }
  async function until(expression) {
    for (let i = 0; i < 100; i++) {
      if (await evaluate(expression)) return;
      await pause(100);
    }
    throw new Error('Condition timed out: ' + expression + '\nBrowser exceptions: ' +
      JSON.stringify(exceptions) + '\nPage: ' + await evaluate('document.body.innerText.slice(-4500)'));
  }
  await cdp('Runtime.enable');await cdp('Page.enable');await cdp('Network.enable');
  await cdp('Emulation.setDeviceMetricsOverride',{width:1440,height:1100,deviceScaleFactor:1,mobile:false});
  await mkdir((testOutput + '/angular22'),{recursive:true});
  await cdp('Page.navigate',{url:baseUrl+'/login'});await until(`!!document.querySelector('#password')`);
  await evaluate(`document.querySelector('#password').value='preview-only';document.querySelector('form').submit()`);await until(`!!document.querySelector('ndr-chart')`);
  assert.equal(await evaluate(`document.querySelector('ndr-root').getAttribute('ng-version')`),'22.2.4');
  async function pointerClick(selector){
    await pause(350);const point=await evaluate(`(()=>{const e=document.querySelector(${JSON.stringify(selector)});if(!e)throw new Error('Missing '+${JSON.stringify(selector)});e.scrollIntoView({block:'center',inline:'center'});const r=e.getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2}})()`);
    await cdp('Input.dispatchMouseEvent',{type:'mouseMoved',...point});
    await cdp('Input.dispatchMouseEvent',{type:'mousePressed',...point,button:'left',clickCount:1});
    await cdp('Input.dispatchMouseEvent',{type:'mouseReleased',...point,button:'left',clickCount:1});
  }
  async function shot(name){const {data}=await cdp('Page.captureScreenshot',{format:'png'});await writeFile((testOutput + '/angular22/')+name,Buffer.from(data,'base64'));}
  await pointerClick('[data-page="alerts"]');await until(`!!document.querySelector('ndr-events tbody tr.clickable')`);
  assert.equal(await evaluate(`document.querySelector('[aria-label="搜索查询"]').type`),'search');assert.equal(await evaluate(`document.querySelector('[aria-label="搜索查询"]').getAttribute('data-1p-ignore')`),'true');
  await pointerClick('ndr-events tbody tr.clickable');await until(`!!document.querySelector('.incident-heading')`);
  await until(`document.querySelector('#detail-panel-network .flow-state')?.textContent.trim()==='closed'`);
  assert.equal(await evaluate(`document.querySelector('#detail-panel-network .summary-text').textContent`),'连接 tls');
  assert.equal(await evaluate(`document.querySelector('#detail-panel-network .flow-state').closest('td').textContent.includes(' \u00b7 ')`),false);
  await pointerClick('#detail-tab-alerts');await until(`!!document.querySelector('#detail-panel-alerts tbody tr')`);
  await evaluate(`document.querySelector('ndr-details .modal-scroll').addEventListener('click',e=>{if(e.target.closest('#detail-panel-alerts tbody'))window.returnScroll=e.currentTarget.scrollTop},true)`);
  await pointerClick('#detail-panel-alerts tbody tr .row-command button');await until(`!!document.querySelector('.evidence-fields')`);
  const labels=await evaluate(`[...document.querySelectorAll('.evidence-fields dt')].map(e=>e.textContent)`);
  assert.ok(labels.includes('应用'));assert.ok(labels.includes('目的端口'));assert.ok(labels.includes('通信方向')===false);assert.ok(!labels.includes('app'));assert.ok(!labels.includes('issuer'));
  assert.equal(await evaluate(`document.querySelector('.raw-evidence').open`),false);
  assert.equal(await evaluate(`!!document.querySelector('.modal-head .modal-back')`),true);
  assert.equal(await evaluate(`document.querySelector('.detail-actions').getBoundingClientRect().top >= document.querySelector('.modal-head').getBoundingClientRect().bottom+16`),true);
  await shot('evidence-desktop.png');
  await pointerClick('.modal-back');await until(`!!document.querySelector('#detail-panel-alerts')`);
  assert.equal(await evaluate(`Math.abs(document.querySelector('ndr-details .modal-scroll').scrollTop-window.returnScroll)<3`),true);
  await pointerClick('#detail-panel-alerts tbody tr .row-command button');await until(`!!document.querySelector('.evidence-fields')`);
  await pointerClick('ndr-details [aria-label="关闭"]');assert.equal(await evaluate(`!!document.querySelector('ndr-details dialog')`),false);
  console.log('ok - translated grouped evidence, hidden empty fields, collapsed raw JSON, header back and scroll/tab restoration');

  const fixture={ts:1793449317,type:'alert',sev:1,app:'http',proto:'TCP',action:'blocked',src:'2001:db8::1',sport:51000,dst:'198.51.100.1',dport:80,sig_id:2100498,sig:'UX fixture',flow_id:1001,dir:'to_server',clen:0,method:'GET',status:200,host:'example.test',url:'/test',httpver:'HTTP/1.1',ct:'text/plain',iif:'eth0',issuer:'',alpn:'',_raw:'{"event_type":"alert","alert":{"action":"blocked"}}'};
  let huntFixture=fixture;
  let held=[];let holdRule=false;let failRule=false;
  route=async p=>{
    const url=new URL(p.request.url);
    if(url.pathname==='/api/hunt')return cdp('Fetch.fulfillRequest',{requestId:p.requestId,responseCode:200,responseHeaders:[{name:'Content-Type',value:'application/json'}],body:Buffer.from(JSON.stringify({events:[huntFixture],total:1,range:[1793400000,1793500000]})).toString('base64')});
    if(url.pathname==='/api/rules/search'&&holdRule){held.push(p.requestId);return;}
    if(url.pathname==='/api/rules/search'&&failRule)return cdp('Fetch.fulfillRequest',{requestId:p.requestId,responseCode:503,responseHeaders:[{name:'Content-Type',value:'application/json'}],body:Buffer.from(JSON.stringify({error:'详情接口测试失败'})).toString('base64')});
    return cdp('Fetch.continueRequest',{requestId:p.requestId});
  };
  await cdp('Fetch.enable',{patterns:[{urlPattern:'*/api/hunt?*'},{urlPattern:'*/api/rules/search?*'}]});
  await pointerClick('[data-page="hunt"]');await until(`document.querySelector('ndr-events tbody')?.textContent.includes('UX fixture')`);
  await pointerClick('ndr-events>section:last-of-type tbody tr .row-command button');await until(`!!document.querySelector('.evidence-fields')`);
  const fields=await evaluate(`Object.fromEntries([...document.querySelectorAll('.evidence-fields>div')].map(e=>[e.querySelector('dt').textContent,e.querySelector('dd').textContent]))`);
  assert.equal(fields['应用'],'HTTP');assert.equal(fields['处置结果'],'已阻断');assert.equal(fields['通信方向'],'客户端 → 服务端');assert.equal(fields['目的端口'],'80');assert.equal(fields['内容长度'],'0 B');assert.equal(fields['采集接口'],'eth0');assert.ok(!('证书签发者' in fields));
  await shot('http-evidence.png');
  holdRule=true;await pointerClick('.detail-actions .quiet:not(.danger)');await until(`!!document.querySelector('.detail-loading')`);await until(`document.querySelector('ndr-details h2')?.textContent.includes('规则详情')`);
  await pointerClick('ndr-details [aria-label="关闭"]');await until(`!document.querySelector('ndr-details dialog')`);
  holdRule=false;for(const requestId of held)await cdp('Fetch.continueRequest',{requestId});held=[];await pause(600);assert.equal(await evaluate(`!!document.querySelector('ndr-details dialog')`),false,'late reply never reopens a dismissed panel');
  await pointerClick('ndr-events>section:last-of-type tbody tr .row-command button');await until(`!!document.querySelector('.evidence-fields')`);
  failRule=true;await pointerClick('.detail-actions .quiet:not(.danger)');await until(`document.querySelector('.detail-error')?.textContent.includes('详情接口测试失败')`);
  failRule=false;await pointerClick('.detail-error button');await until(`document.querySelector('ndr-details pre')?.textContent.includes('sid:2100498')`);
  await pointerClick('ndr-details [aria-label="关闭"]');
  console.log('ok - HTTP translations and zero values, loading, contextual retry and cancelled late response');

  for(const state of ['new','established','closed','bypassed']){
    const protocol=state==='new'?'IPv6-ICMP':'tls',text='连接 '+protocol;
    huntFixture={ts:fixture.ts,type:'flow',proto:state==='new'?'IPv6-ICMP':'TCP',app:state==='new'?'':'tls',sig:text+' [ '+state+' ]',state,flow_id:1001,src:'2001:db8::1',dst:'2001:db8::2',_raw:JSON.stringify({event_type:'flow',flow:{state}})};
    await evaluate(`document.querySelector('ndr-events form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}))`);
    await until(`document.querySelector('ndr-events .flow-state')?.textContent.trim()===${JSON.stringify(state)}`);
    assert.equal(await evaluate(`document.querySelector('ndr-events .summary-text').textContent`),text);
    assert.equal(await evaluate(`getComputedStyle(document.querySelector('ndr-events .flow-state')).borderTopStyle`),'solid');
    assert.equal(await evaluate(`document.querySelector('ndr-events .flow-state').closest('td').textContent.includes(' \u00b7 ')`),false);
    await pointerClick('ndr-events>section:last-of-type tbody tr .row-command button');await until(`!!document.querySelector('.evidence-heading .flow-state')`);
    assert.equal(await evaluate(`document.querySelector('.evidence-heading .summary-text').textContent`),text);
    assert.equal(await evaluate(`document.querySelector('.evidence-heading .flow-state').textContent.trim()`),state);
    const evidence=await evaluate(`Object.fromEntries([...document.querySelectorAll('.evidence-fields>div')].map(e=>{const dd=e.querySelector('dd'),summary=dd.querySelector('ndr-connection-summary');return [e.querySelector('dt').textContent,summary?[...summary.children].map(c=>c.textContent.trim()).join(' '):dd.textContent.trim()]}))`);
    assert.equal(evidence['连接摘要'],text+' '+state);assert.equal(evidence['连接状态'],state);
    assert.equal(await evaluate(`[...document.querySelectorAll('.evidence-fields .flow-state')].every(e=>e.textContent.trim()===${JSON.stringify(state)}&&getComputedStyle(e).borderTopStyle==='solid')`),true);
    assert.equal(await evaluate(`JSON.parse(document.querySelector('.raw-evidence pre').textContent).flow.state`),state);
    await cdp('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true});
    assert.equal(await evaluate(`document.querySelector('ndr-details dialog').scrollWidth<=innerWidth`),true);
    assert.equal(await evaluate(`(()=>{const b=document.querySelector('.evidence-heading .flow-state').getBoundingClientRect(),d=document.querySelector('ndr-details dialog').getBoundingClientRect();return b.left>=d.left&&b.right<=d.right})()`),true);
    await pause(350);await shot('connection-'+state+'-mobile.png');
    await cdp('Emulation.setDeviceMetricsOverride',{width:1440,height:1100,deviceScaleFactor:1,mobile:false});
    await pointerClick('ndr-details [aria-label="关闭"]');
    await shot('connection-'+state+'-desktop.png');
  }
  for(const signature of ['连接 failed \u00b7 established','连接 UDP [ established ] 应用协议识别失败']){
    huntFixture={...huntFixture,app:'failed',proto:'UDP',state:'established',reason:'timeout',sig:signature,_raw:JSON.stringify({type:'flow',state:'established',sig:'连接 UDP [ established ] 应用协议识别失败'})};
    await evaluate(`document.querySelector('ndr-events form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}))`);
    await until(`document.querySelector('ndr-events .summary-text')?.textContent==='连接 UDP'`);
    assert.equal(await evaluate(`document.querySelector('ndr-events .flow-state').textContent.trim()`),'established');
    assert.equal(await evaluate(`document.querySelector('ndr-events .summary-details').textContent.trim()`),'应用协议识别失败');
    assert.equal(await evaluate(`document.querySelector('ndr-events .flow-state').closest('td').textContent.includes('\u00b7')`),false);
    await pointerClick('ndr-events>section:last-of-type tbody tr .row-command button');await until(`!!document.querySelector('.evidence-heading .flow-state')`);
    assert.equal(await evaluate(`document.querySelector('.evidence-heading .summary-text').textContent`),'连接 UDP');
    const evidence=await evaluate(`Object.fromEntries([...document.querySelectorAll('.evidence-fields>div')].map(e=>{const dd=e.querySelector('dd'),summary=dd.querySelector('ndr-connection-summary');return [e.querySelector('dt').textContent,summary?[...summary.children].map(c=>c.textContent.trim()).join(' '):dd.textContent.trim()]}))`);
    assert.equal(evidence['连接摘要'],'连接 UDP established 应用协议识别失败');
    assert.equal(await evaluate(`[...document.querySelectorAll('ndr-details .flow-state')].every(e=>e.textContent.trim()==='established'&&getComputedStyle(e).borderTopStyle==='solid')`),true);
    assert.equal(await evaluate(`JSON.parse(document.querySelector('.raw-evidence pre').textContent).sig`),'连接 UDP [ established ] 应用协议识别失败');
    assert.equal(evidence['应用'],'FAILED（应用协议识别失败）');assert.equal(evidence['连接结束原因'],'timeout');
    await pointerClick('ndr-details [aria-label="关闭"]');
  }
  huntFixture={...huntFixture,app:'tls',proto:'TCP',state:'',sig:'连接 tls'};
  await evaluate(`document.querySelector('ndr-events form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}))`);
  await until(`document.querySelector('ndr-events .summary-text')?.textContent==='连接 tls'&&!document.querySelector('ndr-events .flow-state')`);
  huntFixture={...fixture,sig:'Signature \u00b7 established',state:'established'};
  await evaluate(`document.querySelector('ndr-events form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}))`);
  await until(`document.querySelector('ndr-events tbody')?.textContent.includes('Signature \u00b7 established')`);
  assert.equal(await evaluate(`!!document.querySelector('ndr-events .flow-state')`),false);
  huntFixture=fixture;
  console.log('ok - connection state badges, complete protocol labels, mobile fit, absent states, unchanged signatures and raw evidence');

  // A sparse record should not offer operations that need an address or flow.
  delete fixture.src;delete fixture.dst;delete fixture.flow_id;delete fixture.sig_id;fixture.sig='Sparse fixture';
  await evaluate(`document.querySelector('ndr-events form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}))`);
  await until(`document.querySelector('ndr-events tbody')?.textContent.includes('Sparse fixture')`);
  await pointerClick('ndr-events>section:last-of-type tbody tr .row-command button');await until(`!!document.querySelector('.evidence-fields')`);
  assert.equal(await evaluate(`[...document.querySelectorAll('.detail-actions button')].every(b=>b.disabled)`),true);
  await cdp('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true});
  assert.equal(await evaluate(`document.querySelector('ndr-details dialog').scrollWidth<=innerWidth`),true);
  await shot('evidence-mobile.png');await pointerClick('ndr-details [aria-label="关闭"]');
  await cdp('Fetch.disable');
  await cdp('Emulation.setDeviceMetricsOverride',{width:1440,height:1100,deviceScaleFactor:1,mobile:false});
  console.log('ok - sparse-record actions disabled and evidence layout fits mobile');

  await evaluate(`document.querySelector('ndr-events [aria-label="搜索查询"]').value='flow:1001';document.querySelector('ndr-events [aria-label="搜索查询"]').dispatchEvent(new Event('input',{bubbles:true}));document.querySelector('ndr-events form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}))`);
  await pointerClick('[data-page="system"]');await until(`!!document.querySelector('ndr-system .system-grid')`);
  await pointerClick('[data-page="hunt"]');await until(`!!document.querySelector('ndr-events [aria-label="搜索查询"]')`);
  assert.equal(await evaluate(`document.querySelector('ndr-events [aria-label="搜索查询"]').value`),'flow:1001');
  await pointerClick('[data-page="rules"]');await until(`!!document.querySelector('ndr-rules tbody tr input')`);
  await pointerClick('ndr-rules tbody tr input');await pointerClick('ndr-rules .pager button:last-child');await until(`document.querySelector('ndr-rules .pager').textContent.includes('2 / 3')`);
  await pointerClick('[data-page="overview"]');await pointerClick('[data-page="rules"]');await until(`document.querySelector('ndr-rules .pager').textContent.includes('2 / 3')`);
  assert.equal(await evaluate(`document.querySelector('.selection-bar').textContent.includes('已选 1')`),true);
  await cdp('Page.navigate',{url:baseUrl+'/#alerts'});await until(`!!document.querySelector('ndr-events tbody tr.clickable')`);
  await evaluate(`document.querySelector('ndr-events tbody tr').focus()`);
  await cdp('Input.dispatchKeyEvent',{type:'keyDown',key:'Enter',code:'Enter',windowsVirtualKeyCode:13});await cdp('Input.dispatchKeyEvent',{type:'keyUp',key:'Enter',code:'Enter',windowsVirtualKeyCode:13});
  await until(`!!document.querySelector('.incident-heading')`);await pointerClick('#detail-tab-signatures');
  await until(`!!document.querySelector('#detail-panel-signatures')`);
  await cdp('Input.dispatchKeyEvent',{type:'keyDown',key:'ArrowLeft',code:'ArrowLeft',windowsVirtualKeyCode:37});await cdp('Input.dispatchKeyEvent',{type:'keyUp',key:'ArrowLeft',code:'ArrowLeft',windowsVirtualKeyCode:37});
  await until(`!!document.querySelector('#detail-panel-alerts')`);assert.equal(await evaluate(`document.activeElement.id`),'detail-tab-alerts');
  await shot('incident-tabs.png');assert.deepEqual(exceptions,[]);
  await writeFile((testOutput + '/angular22/ux-results.json'),JSON.stringify({ok:true,framework:'Angular 22.2.4',groupedChineseFields:true,emptyFieldsHidden:true,zeroValuesPreserved:true,headerNavigation:true,scrollAndTabRestored:true,closeCancelsLateReply:true,loadRetry:true,sparseActionsDisabled:true,mobileEvidence:true,queryAndSelectionState:true,keyboardRowsAndTabs:true,uncaughtExceptions:exceptions},null,2));
  console.log('ok - query/page/selection persistence, keyboard rows and detail tabs, Angular 22 and no uncaught errors');
} finally {
 if(ws)ws.close();chrome.kill();await pause(500);const resolved=path.resolve(profile);assert.ok(resolved.startsWith(path.resolve(tmpdir())+path.sep)&&path.basename(resolved).startsWith('ndr-chrome-'));await rm(resolved,{recursive:true,force:true,maxRetries:5,retryDelay:200}).catch(()=>{});
}
