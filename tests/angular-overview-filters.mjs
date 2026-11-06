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
  assert.equal(await evaluate(`document.querySelector('ndr-overview ndr-range')`),null);
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
  const filterStatus = '[data-testid="overview-filter-status"]';
  const untilFiltered = condition => until(`!document.querySelector('${filterStatus}') && (${condition})`);
  const overview=await api('/api/overview?window=15');
  assert.ok(overview.recent.some(r=>r.sig_id===498),'native reject-only fixture exists');
  assert.equal(overview.security.alerts,overview.series.reduce((sum,p)=>sum+p.alerts,0));
  assert.equal(overview.security.drops,overview.series.reduce((sum,p)=>sum+p.drops,0));
  await pointerClick('.resource-summary .stat-card.blocked');
  await untilFiltered(`document.querySelector('.overview-filters')?.textContent.includes('阻断事件')&&!!document.querySelector('[data-testid="alerts-total"]')`);
  assert.equal(await evaluate('location.hash'),'#overview');
  assert.equal(await evaluate(`document.querySelector('.resource-summary .stat-card.blocked').getAttribute('aria-pressed')`),'true');
  assert.equal(await evaluate(`getComputedStyle(document.querySelector('.resource-summary .stat-card.blocked')).outlineStyle`),'none','overview filter cards have no selection frame');
  if(process.env.NDR_TEST_OUTPUT){await mkdir(process.env.NDR_TEST_OUTPUT,{recursive:true});await writeFile(path.join(process.env.NDR_TEST_OUTPUT,'overview-cards.png'),Buffer.from((await cdp('Page.captureScreenshot',{format:'png'})).data,'base64'));}
  await until(`!!document.querySelector('#recent tbody tr')`);
  assert.ok(await evaluate(`[...document.querySelectorAll('#recent tbody tr')].some(e=>e.textContent.includes('阻断'))`),'the selected cohort contains blocked logs');
  await evaluate(`[...document.querySelectorAll('.overview-filters button')].find(b=>b.textContent==='清除筛选').click()`);
  await untilFiltered(`!document.querySelector('.overview-filters')&&!!document.querySelector('.three-grid ndr-chart')`);
  await evaluate(`document.querySelector('.three-grid ndr-chart').scrollIntoView({block:'center'})`);
  await until(`!!document.querySelector('.three-grid ndr-chart path[fill="#4c8157"]')`);
  await pointerBar('.three-grid ndr-chart','#4c8157');
  await untilFiltered(`document.querySelector('.overview-filters')?.textContent.includes('签名 ')&&!!document.querySelector('#recent tbody tr')`);
  assert.equal(await evaluate('location.hash'),'#overview');
  await evaluate(`[...document.querySelectorAll('.overview-filters button')].find(b=>b.textContent==='清除筛选').click()`);
  await untilFiltered(`!document.querySelector('.overview-filters')&&!!document.querySelector('.trend ndr-chart')`);
  await evaluate(`document.querySelector('.trend ndr-chart').scrollIntoView({block:'center'})`);
  await until(`!!document.querySelector('.trend path[fill="#724e26"]')`);
  await pointerBar('.trend ndr-chart','#724e26');
  await untilFiltered(`document.querySelector('.overview-filters')?.textContent.includes(' 至 ')&&!!document.querySelector('[data-testid="alerts-total"]')`);
  assert.equal(await evaluate('location.hash'),'#overview');
  await evaluate(`[...document.querySelectorAll('.overview-filters button')].find(b=>b.textContent==='清除筛选').click()`);
  await untilFiltered(`!document.querySelector('.overview-filters')&&!!document.querySelector('.three-grid .chart-view-toggle')`);
  await until(`document.querySelector('.visibility-grid h2')?.textContent==='连接应用分布'`);
  await evaluate(`document.querySelector('.visibility-grid ndr-chart')?.scrollIntoView({block:'center'})`);
  await until(`!!document.querySelector('.visibility-grid ndr-chart path[fill="#4c8157"]')`);
  await pointerBar('.visibility-grid ndr-chart','#4c8157');
  await untilFiltered(`document.querySelector('.overview-filters')?.textContent.includes('连接应用分布')&&!!document.querySelector('.network-summary')`);
  assert.equal(await evaluate('location.hash'),'#overview');
  assert.ok(Number(await evaluate(`document.querySelector('[data-testid="alerts-total"]').textContent.replace(/,/g,'').trim()`))>0,'application filtering retains detections from matching connections');
  if(process.env.NDR_TEST_OUTPUT){await mkdir(process.env.NDR_TEST_OUTPUT,{recursive:true});await writeFile(path.join(process.env.NDR_TEST_OUTPUT,'overview-filters.png'),Buffer.from((await cdp('Page.captureScreenshot',{format:'png'})).data,'base64'));}
  await evaluate(`[...document.querySelectorAll('.overview-filters button')].find(b=>b.textContent==='清除筛选').click()`);
  await untilFiltered(`!document.querySelector('.overview-filters')&&!!document.querySelector('.three-grid .chart-view-toggle')`);
  await pointerClick('.three-grid .chart-view-toggle');
  await until(`!!document.querySelector('.three-grid ndr-table tbody tr.clickable')`);
  await pointerClick('.three-grid ndr-table tbody tr.clickable');
  await untilFiltered(`location.hash==='#overview'&&document.querySelector('.overview-filters')?.textContent.includes('签名')`);
  await evaluate(`[...document.querySelectorAll('.overview-filters button')].find(b=>b.textContent==='清除筛选').click()`);
  await untilFiltered(`!!document.querySelector('#recent tbody tr.clickable')`);
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
  await pointerClick('[data-page="overview"]');
  await evaluate(`document.querySelector('.overview-filters button:last-child')?.click()`);
  await untilFiltered(`!document.querySelector('.overview-filters')&&!!document.querySelector('.three-grid')`);
  async function card(title){
    await until(`[...document.querySelectorAll('ndr-overview section.card h2')].some(e=>e.textContent.trim()===${JSON.stringify(title)})`);
    return evaluate(`(()=>{const e=[...document.querySelectorAll('ndr-overview section.card')].find(e=>e.querySelector('h2')?.textContent.trim()===${JSON.stringify(title)});if(!e)throw Error('Missing '+${JSON.stringify(title)});e.dataset.testcard='selected';return true;})()`);
  }
  await card('高频源地址');await evaluate(`document.querySelector('[data-testcard="selected"] .chart-view-toggle').click()`);
  await until(`document.querySelector('[data-testcard="selected"] tbody tr')?.textContent.includes('192.0.2.55')`);
  await evaluate(`(()=>{const card=document.querySelector('[data-testcard="selected"]');card.querySelector('tbody tr').click();card.removeAttribute('data-testcard');})()`);
  await untilFiltered(`document.querySelector('.overview-filters')?.textContent.includes('192.0.2.55')&&document.querySelector('#recent tbody')?.textContent.includes('HTTP')`);
  assert.equal(await evaluate(`document.querySelector('[data-testid="alerts-total"]').textContent.trim()`),'0','ordinary high-frequency logs are not alert ranks');
  await evaluate(`[...document.querySelectorAll('.overview-filters button')].find(b=>b.textContent==='清除筛选').click()`);
  await untilFiltered(`!document.querySelector('.overview-filters')`);
  await card('高频 DNS 域名');await evaluate(`document.querySelector('[data-testcard="selected"] .chart-view-toggle').click()`);
  await until(`document.querySelector('[data-testcard="selected"] tbody')?.textContent.includes('udp.example.test')`);
  await evaluate(`(()=>{const card=document.querySelector('[data-testcard="selected"]'),row=[...card.querySelectorAll('tbody tr')].find(e=>e.textContent.includes('udp.example.test'));row.click();card.removeAttribute('data-testcard');})()`);
  await untilFiltered(`document.querySelector('.overview-filters')?.textContent.includes('udp.example.test')&&document.querySelector('#network-sources tbody')?.textContent.includes('192.0.2.53')&&document.querySelector('#recent tbody')?.textContent.includes('DNS')`);
  await card('连接传输协议');await evaluate(`document.querySelector('[data-testcard="selected"] .chart-view-toggle').click()`);
  await until(`document.querySelector('[data-testcard="selected"] tbody')?.textContent.includes('UDP')`);
  await pointerClick('[data-page="alerts"]');await until(`!!document.querySelector('ndr-events tbody tr')`);
  const download=path.join(process.env.NDR_TEST_OUTPUT||profile,'downloads');await mkdir(download,{recursive:true});
  await cdp('Browser.setDownloadBehavior',{behavior:'allow',downloadPath:download});
  await evaluate(`[...document.querySelectorAll('ndr-events button')].find(e=>e.textContent.includes('导出原始告警')).click()`);
  let exported='';for(let index=0;index<100;index++){try{exported=await readFile(path.join(download,'snort-alerts.csv'),'utf8');break;}catch{await pause(100);}}
  assert.ok(exported.includes('Native reject only'),'downloaded CSV includes blocked native detections');
  assert.ok(exported.includes('time,type,severity,sid,signature'),'download contains CSV rows and headers');
  assert.equal(await evaluate(`document.querySelector('ndr-events .chart-spinner')`),null);

  // Drive the overview stream one message at a time so pending states are observable.
  await execute(`
    const NativeEventSource = window.EventSource;
    window.EventSource = class extends EventTarget {
      static OPEN = NativeEventSource.OPEN;
      readyState = NativeEventSource.CONNECTING;
      constructor(url) {
        super();
        const params = new URL(url, location.href).searchParams;
        if (params.get('topic') !== 'overview') return new NativeEventSource(url);
        window.overviewTestParams = Object.fromEntries(params);
        window.overviewTestStream = this;
      }
      close() { this.readyState = NativeEventSource.CLOSED; }
    };
    document.querySelector('[data-page="overview"]').click();
  `);
  const redAlert = 'ndr-overview .error[role="alert"]';
  await until(`!!window.overviewTestStream && !!document.querySelector('ndr-overview')`);
  assert.deepEqual(await evaluate('window.overviewTestParams'),{window:'1440',view:'panel',topic:'overview'});
  const waitingText = /正在加载|正在准备网络统计|等待重试|正在重试|更新延迟|正在更新/;
  assert.doesNotMatch(await evaluate(`document.querySelector('ndr-overview').innerText`),waitingText);
  assert.equal(await evaluate(`document.querySelector(${JSON.stringify(redAlert)})`),null,'waiting for the first chart shows no error');

  const emitOverview = payload => execute(`
    window.overviewTestStream.readyState = EventSource.OPEN;
    window.overviewTestStream.onmessage({data: ${JSON.stringify(JSON.stringify(payload))}});
  `);
  const errorText = `document.querySelector(${JSON.stringify(redAlert)})?.textContent`;
  await emitOverview({error:'实时连接中断'});
  await until(`${errorText}?.includes('实时连接中断') && !document.querySelector('ndr-overview .chart-spinner')`);

  await emitOverview({...overview,network:{available:false,status:'pending'}});
  await until(`!!document.querySelector('ndr-overview .trend ndr-chart') && !(${errorText})`);
  assert.equal(await evaluate(`document.querySelector('.network-summary strong').textContent.trim()`),'—');
  assert.ok(await evaluate(`document.querySelector('.network-summary').compareDocumentPosition(document.querySelector('ndr-overview .three-grid')) & Node.DOCUMENT_POSITION_FOLLOWING`));

  const networkTimeout = '网络统计更新失败：网络统计计算超时';
  await emitOverview({...overview,network:{available:false,status:'error',error:networkTimeout,retry_seconds:30,refreshing:false}});
  assert.equal(await evaluate(`document.querySelector('.network-summary strong').textContent.trim()`),'—');
  assert.equal(await evaluate(errorText),undefined);
  await emitOverview({...overview,network:{...overview.network,available:true,partial:true,flows:37,tls:12,
    status:'stale',error:networkTimeout,retry_seconds:0,refreshing:true}});
  await until(`!!document.querySelector('.visibility-grid ndr-chart') && !(${errorText})`);
  const counts = await evaluate(`[...document.querySelectorAll('.network-summary strong')].map(e=>e.textContent.trim())`);
  assert.equal(counts[0],'37');
  assert.equal(counts[3],'12');
  assert.equal(await evaluate(`[...document.querySelectorAll('.visibility-grid h2')].some(e=>e.textContent==='连接应用分布')`),false);
  assert.doesNotMatch(await evaluate(`document.querySelector('.network-update').innerText`),waitingText);
  await emitOverview({...overview,network:{available:false,status:'error',error:'事件库不可用'}});
  await until(`${errorText}?.includes('事件库不可用')`);

  const settledNetwork = {...overview.network,available:true,status:'ready',error:''};
  await emitOverview({...overview,network:settledNetwork,read_state:{status:'stale',as_of:1}});
  await until(`!!document.querySelector('.trend ndr-chart svg') && !(${errorText})`);
  assert.doesNotMatch(await evaluate(`document.querySelector('.trend').innerText`),waitingText);
  await emitOverview({...overview,network:settledNetwork,read_state:{status:'stale',error:'读取失败'}});
  await until(`${errorText}?.includes('读取失败') && !document.querySelector('ndr-overview .chart-spinner')`);
  await emitOverview({...overview,network:settledNetwork});
  await until(`!!document.querySelector('.trend ndr-chart svg') && !document.querySelector('ndr-overview .chart-spinner') && !(${errorText})`);
  const alertCount = '[data-testid="alerts-total"]';
  const oldCount = await evaluate(`document.querySelector('${alertCount}').textContent.trim()`);
  await evaluate(`document.querySelector('.resource-summary .stat-card.blocked').click()`);
  await until(`window.overviewTestParams.detection==='drops' && document.querySelector('${filterStatus}')?.textContent.includes('暂显示上一次结果')`);
  assert.equal(await evaluate(`document.querySelector('${alertCount}').textContent.trim()`),oldCount);
  await emitOverview({...overview,security:{alerts:0,error:'筛选查询超时'}});
  await until(`${errorText}?.includes('筛选查询超时') && document.querySelector('${filterStatus}')?.textContent.includes('当前筛选尚无结果')`);
  assert.equal(await evaluate(`document.querySelector('${alertCount}').textContent.trim()`),oldCount);
  await emitOverview({...overview,security:{...overview.security,alerts:987},network:settledNetwork});
  await until(`!document.querySelector('${filterStatus}') && document.querySelector('${alertCount}')?.textContent.trim()==='987'`);
  assert.deepEqual(exceptions,[]);
  console.log('PASS: overview chart loading and error states, log-based ranks, session-cohort filters, DNS-to-UDP statistics, evidence details and native-alert CSV download');
} finally {
 if(ws)ws.close();chrome.kill();await pause(500);const resolved=path.resolve(profile);assert.ok(resolved.startsWith(path.resolve(tmpdir())+path.sep)&&path.basename(resolved).startsWith('ndr-chrome-'));await rm(resolved,{recursive:true,force:true,maxRetries:5,retryDelay:200}).catch(()=>{});
}
