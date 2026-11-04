// Dependency-free Chrome DevTools smoke test. Start serve_preview.py first.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, writeFile, mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
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
  ws.onmessage = ({ data }) => {
    const message = JSON.parse(data);
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
  await cdp('Runtime.enable');await cdp('Page.enable');
  await cdp('Emulation.setDeviceMetricsOverride',{width:1440,height:1100,deviceScaleFactor:1,mobile:false});
  await cdp('Page.navigate',{url:(process.env.NDR_PREVIEW_URL||'http://127.0.0.1:19090')+'/login'});await until(`!!document.querySelector('#password')`);
  await evaluate(`document.querySelector('#password').value='preview-only';document.querySelector('form').submit()`);await until(`!!document.querySelector('ndr-chart')`);
  async function pointerClick(selector){
    await pause(350);const point=await evaluate(`(()=>{const e=document.querySelector(${JSON.stringify(selector)});if(!e)throw new Error('Missing '+${JSON.stringify(selector)});e.scrollIntoView({block:'center',inline:'center'});const r=e.getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2}})()`);
    await cdp('Input.dispatchMouseEvent',{type:'mouseMoved',...point});
    await cdp('Input.dispatchMouseEvent',{type:'mousePressed',...point,button:'left',clickCount:1});
    await cdp('Input.dispatchMouseEvent',{type:'mouseReleased',...point,button:'left',clickCount:1});
  }


  async function pointerBar(scope,fill){
    await evaluate(`document.querySelector(${JSON.stringify(scope)}).scrollIntoView({block:'center'})`);await pause(400);
    const point=await evaluate(`(()=>{const e=[...document.querySelectorAll(${JSON.stringify(scope+' path[fill="'+fill+'"]')})].find(e=>{const r=e.getBoundingClientRect();return r.width>3&&r.height>3&&getComputedStyle(e).opacity!=='0'});if(!e)throw new Error('Missing positive bar');const r=e.getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2}})()`);
    await cdp('Input.dispatchMouseEvent',{type:'mouseMoved',...point});
    await cdp('Input.dispatchMouseEvent',{type:'mousePressed',...point,button:'left',clickCount:1});
    await cdp('Input.dispatchMouseEvent',{type:'mouseReleased',...point,button:'left',clickCount:1});
  }
  const api=url=>evaluate(`fetch(${JSON.stringify(url)}).then(r=>r.json())`);
  const overview=await api('/api/overview?window=15');
  assert.ok(overview.recent.some(r=>r.sig_id===498),'native reject-only fixture exists');
  assert.equal(overview.security.alerts,overview.series.reduce((sum,p)=>sum+p.alerts,0));
  assert.equal(overview.security.drops,overview.series.reduce((sum,p)=>sum+p.drops,0));
  await pointerClick('.resource-summary .stat-card.blocked');
  await until(`document.querySelector('.overview-filters')?.textContent.includes('阻断事件')&&!!document.querySelector('[data-testid="alerts-total"]')`);
  assert.equal(await evaluate('location.hash'),'#overview');
  assert.equal(await evaluate(`document.querySelector('.resource-summary .stat-card.blocked').getAttribute('aria-pressed')`),'true');
  assert.equal(await evaluate(`getComputedStyle(document.querySelector('.resource-summary .stat-card.blocked')).outlineStyle`),'none','overview filter cards have no selection frame');
  if(process.env.NDR_TEST_OUTPUT){await mkdir(process.env.NDR_TEST_OUTPUT,{recursive:true});await writeFile(path.join(process.env.NDR_TEST_OUTPUT,'overview-cards.png'),Buffer.from((await cdp('Page.captureScreenshot',{format:'png'})).data,'base64'));}
  await until(`!!document.querySelector('#recent tbody tr')`);
  assert.equal(await evaluate(`[...document.querySelectorAll('#recent tbody tr')].every(e=>e.textContent.includes('阻断'))`),true);
  await evaluate(`[...document.querySelectorAll('.overview-filters button')].find(b=>b.textContent==='清除筛选').click()`);
  await until(`!document.querySelector('.overview-filters')&&!!document.querySelector('.three-grid ndr-chart')`);
  await evaluate(`document.querySelector('.three-grid ndr-chart').scrollIntoView({block:'center'})`);
  await until(`!!document.querySelector('.three-grid ndr-chart path[fill="#4c8157"]')`);
  await pointerBar('.three-grid ndr-chart','#4c8157');
  await until(`document.querySelector('.overview-filters')?.textContent.includes('签名 ')&&!!document.querySelector('#recent tbody tr')`);
  assert.equal(await evaluate('location.hash'),'#overview');
  await evaluate(`[...document.querySelectorAll('.overview-filters button')].find(b=>b.textContent==='清除筛选').click()`);
  await until(`!document.querySelector('.overview-filters')&&!!document.querySelector('.trend ndr-chart')`);
  await evaluate(`document.querySelector('.trend ndr-chart').scrollIntoView({block:'center'})`);
  await until(`!!document.querySelector('.trend path[fill="#724e26"]')`);
  await pointerBar('.trend ndr-chart','#724e26');
  await until(`document.querySelector('.overview-filters')?.textContent.includes(' 至 ')&&!!document.querySelector('[data-testid="alerts-total"]')`);
  assert.equal(await evaluate('location.hash'),'#overview');
  await evaluate(`[...document.querySelectorAll('.overview-filters button')].find(b=>b.textContent==='清除筛选').click()`);
  await until(`!document.querySelector('.overview-filters')&&!!document.querySelector('.three-grid .chart-view-toggle')`);
  await evaluate(`document.querySelector('.visibility-grid ndr-chart')?.scrollIntoView({block:'center'})`);
  await until(`!!document.querySelector('.visibility-grid ndr-chart path[fill="#4c8157"]')`);
  await pointerBar('.visibility-grid ndr-chart','#4c8157');
  await until(`document.querySelector('.overview-filters')?.textContent.includes('连接应用分布')&&!!document.querySelector('.network-summary')`);
  assert.equal(await evaluate('location.hash'),'#overview');
  assert.equal(await evaluate(`document.querySelector('[data-testid="alerts-total"]').textContent.trim()`),'0','flow filtering does not leave unrelated security counts');
  if(process.env.NDR_TEST_OUTPUT){await mkdir(process.env.NDR_TEST_OUTPUT,{recursive:true});await writeFile(path.join(process.env.NDR_TEST_OUTPUT,'overview-filters.png'),Buffer.from((await cdp('Page.captureScreenshot',{format:'png'})).data,'base64'));}
  await evaluate(`[...document.querySelectorAll('.overview-filters button')].find(b=>b.textContent==='清除筛选').click()`);
  await until(`!document.querySelector('.overview-filters')&&!!document.querySelector('.three-grid .chart-view-toggle')`);
  await pointerClick('.three-grid .chart-view-toggle');
  await until(`!!document.querySelector('.three-grid ndr-table tbody tr.clickable')`);
  await pointerClick('.three-grid ndr-table tbody tr.clickable');
  await until(`location.hash==='#hunt'&&!!document.querySelector('ndr-hunt-query input')`);
  assert.match(await evaluate(`document.querySelector('ndr-hunt-query input').value`),/sid:/,'text list keeps original investigation');
  await pointerClick('[data-page="overview"]');await until(`!!document.querySelector('#recent tbody tr.clickable')`);
  await pointerClick('#recent tbody tr.clickable');await until(`!!document.querySelector('ndr-details ndr-modal')`);
  assert.equal(await evaluate('location.hash'),'#overview','latest text record keeps detail dialog');
  await until(`!!document.querySelector('ndr-details .evidence-fields')`);
  const evidence=await evaluate(`Object.fromEntries([...document.querySelectorAll('ndr-details .evidence-fields > div')].map(e=>[e.querySelector('dt').textContent,e.querySelector('dd').textContent]))`);
  assert.equal(evidence['引擎处置动作'],'重置连接（reset）');
  assert.equal(evidence['规则动作'],'主动拒绝（reject）');
  assert.equal(evidence['阻断原因'],undefined,'native action is not labelled as a cause');
  assert.ok((await evaluate(`document.querySelector('ndr-details pre').textContent`)).includes('"action": "reset"'),'original native action retained');
  await evaluate(`document.querySelector('ndr-details .modal-head button[aria-label="关闭"]').click()`);
  await pointerClick('[data-page="drops"]');
  const dropReasons='ndr-events .three-grid > section:first-child ndr-table';
  await until(`!!document.querySelector('${dropReasons} tbody tr.clickable')`);
  assert.ok((await evaluate(`document.querySelector('${dropReasons}').textContent`)).includes('重置连接（reset）'));
  await pointerClick(dropReasons+' tbody tr.clickable:has(td[title="重置连接（reset）"])');
  await until(`location.hash==='#hunt'&&!!document.querySelector('ndr-hunt-query input')`);
  assert.equal(await evaluate(`document.querySelector('ndr-hunt-query input').value`),'type: drop AND reason: "reset"','translated action still filters by original value');
  assert.deepEqual(exceptions,[]);
  console.log('PASS: overview filters, navigation, evidence action labels, unchanged raw data and drop action filtering');
} finally {
 if(ws)ws.close();chrome.kill();await pause(500);const resolved=path.resolve(profile);assert.ok(resolved.startsWith(path.resolve(tmpdir())+path.sep)&&path.basename(resolved).startsWith('ndr-chrome-'));await rm(resolved,{recursive:true,force:true,maxRetries:5,retryDelay:200}).catch(()=>{});
}
