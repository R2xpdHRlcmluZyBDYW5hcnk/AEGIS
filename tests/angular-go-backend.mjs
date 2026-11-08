import {testOutput} from './test-output.mjs';
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
let ws,holdOverview=false;
const heldOverview=[];
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
    if(message.method==='Fetch.requestPaused'){
      if(holdOverview)heldOverview.push(message.params.requestId);
      else void cdp('Fetch.continueRequest',{requestId:message.params.requestId}).catch(()=>{});
      return;
    }
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
  await cdp('Runtime.enable'); await cdp('Page.enable'); await cdp('Network.enable');
  await cdp('Emulation.setDeviceMetricsOverride',{width:1440,height:1100,deviceScaleFactor:1,mobile:false});
  const screenshots=(testOutput + '/angular'); await mkdir(screenshots,{recursive:true});
  async function shot(name){const {data}=await cdp('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});await writeFile(path.join(screenshots,name),Buffer.from(data,'base64'));}
  async function clickText(text,scope='document'){await until(`[...${scope}.querySelectorAll('button')].some(b=>b.textContent.trim()===${JSON.stringify(text)}&&!b.disabled)`);await evaluate(`[...${scope}.querySelectorAll('button')].find(b=>b.textContent.trim()===${JSON.stringify(text)})?.click()`);await until(`[...document.querySelectorAll('ndr-table .table-scroll')].every(e=>e.getAttribute('aria-busy')!=='true')`);}
  async function set(selector,value,event='input'){await evaluate(`(()=>{const e=document.querySelector(${JSON.stringify(selector)});if(!e)throw new Error('Missing input '+${JSON.stringify(selector)});e.value=${JSON.stringify(value)};e.dispatchEvent(new Event(${JSON.stringify(event)},{bubbles:true}));})()`);}
  async function nav(page){await evaluate(`document.querySelector('[data-page="${page}"]').click()`);await until(`location.hash==='#${page}'`);}
  async function ruleTab(title){await clickText(title,`document.querySelector('ndr-rules .tabs')`);await until(`document.querySelector('ndr-rules .tabs button.active')?.textContent.trim()===${JSON.stringify(title)} && document.querySelector('ndr-rules ndr-table .table-scroll')?.getAttribute('aria-busy')==='false'`);}
  async function closeModal(){await evaluate(`[...document.querySelectorAll('dialog[open]')].at(-1).querySelector('[aria-label="关闭"]').click()`);}
  async function api(url,method='GET',body){return evaluate(`fetch(${JSON.stringify(url)},{method:${JSON.stringify(method)},headers:{'X-Requested-With':'ips-web','Content-Type':'application/json'},${body===undefined?'':`body:JSON.stringify(${JSON.stringify(body)})`}}).then(r=>r.json())`);}
  async function holdOverviewRequests(){holdOverview=true;await cdp('Fetch.enable',{patterns:[{urlPattern:'*/api/overview*',requestStage:'Request'},{urlPattern:'*/api/stream*',requestStage:'Request'}]});}
  async function releaseOverviewRequests(){holdOverview=false;for(const requestId of heldOverview.splice(0))await cdp('Fetch.continueRequest',{requestId});await cdp('Fetch.disable');}

  const base=process.env.NDR_PREVIEW_URL||'http://127.0.0.1:19096';
  await cdp('Page.navigate',{url:base+'/login'});await until(`!!document.querySelector('#password')`);
  await holdOverviewRequests();
  await set('#password','preview-only');await evaluate(`document.querySelector('form').submit()`);
  await until(`!!document.querySelector('[data-testid="overview-loading"]')`);
  assert.equal(await evaluate(`!!document.querySelector('[data-testid="alerts-total"]')`),false,'cold overview shows an explicit loading state');
  assert.deepEqual(await evaluate(`(()=>{
    const e=document.querySelector('[data-testid="overview-loading"]'),svg=e.querySelector('svg'),box=document.querySelector('.content-viewport').getBoundingClientRect(),ring=svg.getBoundingClientRect(),probe=document.createElement('span');
    probe.style.color='var(--green)';e.append(probe);const theme=getComputedStyle(probe).color;probe.remove();
    return {text:e.innerText,label:e.getAttribute('aria-label'),centered:Math.abs(ring.x+ring.width/2-box.x-box.width/2)<1&&Math.abs(ring.y+ring.height/2-box.y-box.height/2)<1,color:getComputedStyle(svg).color===theme,animated:getComputedStyle(svg).animationName!=='none'};
  })()`),{text:'',label:'正在加载概览',centered:true,color:true,animated:true},'cold overview uses a centered accessible theme-colored spinner');
  await cdp('Emulation.setEmulatedMedia',{features:[{name:'prefers-reduced-motion',value:'reduce'}]});
  assert.equal(await evaluate(`getComputedStyle(document.querySelector('.overview-spinner')).animationName`),'none','spinner respects reduced motion');
  await cdp('Emulation.setEmulatedMedia',{features:[]});
  for(const [width,height] of [[1280,800],[1920,1080]]){
    await cdp('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:false});
    assert.equal(await evaluate(`(()=>{const box=document.querySelector('.content-viewport').getBoundingClientRect(),ring=document.querySelector('.overview-spinner').getBoundingClientRect();return Math.abs(ring.x+ring.width/2-box.x-box.width/2)<1&&Math.abs(ring.y+ring.height/2-box.y-box.height/2)<1&&document.documentElement.scrollWidth<=innerWidth;})()`),true,'spinner stays centered in the right content frame at '+width);
  }
  await cdp('Emulation.setDeviceMetricsOverride',{width:1440,height:1100,deviceScaleFactor:1,mobile:false});
  await shot('go-overview-loading.png');
  await releaseOverviewRequests();
  await until(`document.querySelector('[data-testid="alerts-total"]')?.textContent.trim()==='3'`);
  await until(`[...document.querySelectorAll('.network-summary .stat-card strong')].length===4 && [...document.querySelectorAll('.network-summary .stat-card strong')].every(e=>e.textContent.trim()!=='—')`);
  assert.deepEqual(await evaluate(`[...document.querySelectorAll('.network-summary .stat-card strong')].map(e=>e.textContent.trim())`),['1','2','1','1'],'network counters render');
  assert.equal(await evaluate(`document.querySelector('[data-testid="high-total"]').textContent.trim()`),'1');
  assert.equal(await evaluate(`document.querySelector('[data-testid="drops-total"]').textContent.trim()`),'2','suppressed blocking actions remain visible');
  const overview=await api('/api/overview?scope=cache&view=panel');
  assert.equal(overview.security.alerts,3);assert.equal(overview.security.high,1);assert.equal(overview.security.drops,2);
  assert.deepEqual(overview.series.reduce((sum,p)=>[sum[0]+p.alerts,sum[1]+p.drops],[0,0]),[3,2],'alert trend excludes suppression and block trend retains enforcement');
  assert.ok(overview.top.signatures.length>0&&overview.top.signatures.every(r=>!r.sig.includes('suppressed')),'signature ranks exclude suppressed records');
  await until(`!!document.querySelector('ndr-chart .echarts-surface svg')`);
  await shot('go-overview-desktop.png');
  await nav('system');await until(`!!document.querySelector('.database-card')`);
  await holdOverviewRequests();await nav('overview');
  await until(`document.querySelector('[data-testid="alerts-total"]')?.textContent.trim()==='3'`);
  assert.equal(await evaluate(`!!document.querySelector('[data-testid="overview-loading"]')`),false,'returning overview retains its snapshot while requests are held');
  await until(`document.querySelector('[data-testid="overview-filter-status"]')?.textContent.includes('正在更新概览')`);
  await releaseOverviewRequests();await until(`!document.querySelector('[data-testid="overview-filter-status"]')`);
  await nav('alerts');await until(`document.querySelector('ndr-events ndr-table tbody tr')?.textContent.includes('Fixture')`);
  await evaluate(`document.querySelector('ndr-events ndr-table tbody tr').click()`);
  await until(`!!document.querySelector('.incident-heading')`);
  assert.equal(await evaluate(`document.querySelector('dialog').textContent.includes('会话 ID')`),true);
  await shot('go-incident-desktop.png');await closeModal();
  await nav('hunt');await until(`document.querySelectorAll('ndr-events ndr-table tbody tr').length===10`);
  await set('[aria-label="搜索查询"]','proto:tcp AND type:(http OR tls)');await clickText('查询 →');
  await until(`document.querySelectorAll('ndr-events ndr-table tbody tr').length===2`);
  await set('[aria-label="搜索查询"]','unknown_field:bad');await clickText('查询 →');await until(`!!document.querySelector('ndr-events>.error')`);
  await set('[aria-label="搜索查询"]','');await clickText('查询 →');await until(`!document.querySelector('ndr-events>.error')`);
  await nav('drops');await until(`document.querySelectorAll('ndr-events>section:last-of-type ndr-table tbody tr').length===2`);
  assert.ok(await evaluate(`document.querySelector('ndr-events>section:last-of-type').textContent.includes('Fixture suppressed block')`),'suppressed drop remains in the raw block list');
  await nav('rules');await ruleTab('检测签名');await until(`document.querySelectorAll('ndr-rules ndr-table tbody tr').length===50`);
  await clickText('下一页 →',`document.querySelector('ndr-rules ndr-table')`);await until(`document.querySelector('ndr-rules .pager')?.textContent.includes('2 / 3')`);
  await ruleTab('禁用策略');await clickText('＋ 新建');await until(`document.querySelectorAll('ndr-picker tbody input').length===50`);
  await evaluate(`document.querySelector('ndr-picker tbody input').click()`);await clickText('确认保存');await until(`!document.querySelector('ndr-picker')`);
  assert.equal((await api('/api/rules/governance')).disable.length,1);
  const groups=(await api('/api/rules/groups')).groups;assert.ok(groups.some(g=>g.total===125));
  const group=groups.find(g=>g.total===125);assert.equal((await api('/api/rules/suppress-groups','POST',{groups:[group.selector]})).ok,true);
  assert.equal((await api('/api/rules/governance')).suppress_groups[0].total,125);
  assert.equal((await api('/api/hunt/rules','POST',{rule:'alert tcp any any -> any 443 (msg:"Browser fixture"; sid:9900101; rev:1;)'})).ok,true);
  assert.ok((await api('/api/hunt/rules')).rules.some(r=>r.sid===9900101));
  assert.equal((await api('/api/bans','POST',{target:'192.0.2.99'})).ok,true);
  const schedule=await api('/api/rules/schedule','POST',{enabled:true,frequency:'weekly',time:'05:17',weekday:0});assert.equal(schedule.time,'05:17');assert.ok(schedule.next_run>0);
  await api('/api/rules/pending/discard','POST');assert.equal((await api('/api/actions/status')).pending,false);
  await shot('go-rules-desktop.png');
  await nav('system');await until(`!!document.querySelector('.database-card')`);await shot('go-system-desktop.png');
  const health=await api('/healthz');assert.equal(health.backend,'go');assert.equal(health.go_version,'go1.27.3');
  for(const [width,height] of [[1280,800],[1920,1080]]){
    await cdp('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:false});
    for(const page of ['overview','alerts','drops','hunt','rules','system']){await nav(page);await pause(200);assert.equal(await evaluate(`document.documentElement.scrollWidth<=innerWidth`),true,'desktop overflow '+page);}
  }
  for(let i=0;i<12;i++){
    await nav('overview');await pause(10);await nav('hunt');await pause(10);
  }
  await nav('overview');await until(`document.querySelector('[data-testid="alerts-total"]')?.textContent.trim()==='3'`);
  const recoveredHealth=await api('/healthz');assert.equal(recoveredHealth.overview_ready,true);assert.equal(recoveredHealth.recent_events_error,'');assert.equal(recoveredHealth.recent_events_diagnostics.rebuilds,0,'page changes preserve the cache');
  assert.deepEqual(exceptions,[],'no uncaught browser exceptions');
  console.log('ok - Go login, six desktop pages, session details, search, pagination, rule edits, group suppression, manual rules, bans and schedule');
} finally {
  if(ws)ws.close();chrome.kill();await pause(500);
  const resolved=path.resolve(profile);assert.ok(resolved.startsWith(path.resolve(tmpdir())+path.sep)&&path.basename(resolved).startsWith('ndr-chrome-'));
  await rm(resolved,{recursive:true,force:true,maxRetries:5,retryDelay:200}).catch(()=>{});
}
