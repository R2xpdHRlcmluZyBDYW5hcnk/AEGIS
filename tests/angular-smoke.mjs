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
  await cdp('Page.navigate',{url:'http://127.0.0.1:19090/login'});await until(`!!document.querySelector('#password')`);
  await set('#password','preview-only');await evaluate(`document.querySelector('form').submit()`);
  await until(`document.querySelector('[data-testid="alerts-total"]')?.textContent.trim()==='4'`);
  assert.equal(await evaluate(`document.querySelector('ndr-root').getAttribute('ng-version')`),'22.2.4');
  assert.equal(await evaluate(`document.querySelector('[data-testid="high-total"]').textContent.trim()`),'1');
  assert.equal(await evaluate(`document.querySelector('[data-testid="drops-total"]').textContent.trim()`),'1');
  await until(`!!document.querySelector('ndr-chart .echarts-surface svg')`);assert.equal(await evaluate(`document.querySelector('.brand-icon')?.getAttribute('src')`),'/favicon.svg');assert.equal(await evaluate(`!!document.querySelector('.brand-emblem')`),false);
  assert.equal(await evaluate(`!!document.querySelector('canvas,iframe')`),false);
  assert.equal(await evaluate(`typeof window.RulePicker`),'undefined');
  assert.equal(await evaluate(`typeof window.__NDR_TEST__`),'undefined');assert.equal(await evaluate(`document.body.textContent.includes('ANGULAR 17')`),false);
  assert.equal(await evaluate(`getComputedStyle(document.body).backgroundColor`),'rgb(18, 18, 18)');assert.equal(await evaluate(`getComputedStyle(document.querySelector('.sidebar nav button.active')).backgroundColor`),'rgb(67, 116, 75)');await shot('overview-desktop.png');
  await api('/__test/reset','POST');
  console.log('ok - native Angular bootstrap, SVG chart, real fixture counters and no legacy runtime');

  await nav('alerts');await until(`document.querySelector('ndr-events ndr-table tbody tr')?.textContent.includes('Suspicious')`);
  assert.equal(await evaluate(`document.querySelectorAll('ndr-events ndr-table tbody tr').length`),2);
  await evaluate(`document.querySelectorAll('ndr-events ndr-table tbody tr')[1].click()`);await until(`!!document.querySelector('dialog[open] .incident-heading')`);
  assert.equal(await evaluate(`document.querySelector('dialog').textContent.includes('Flow ID')`),true);
  await evaluate(`document.querySelector('ndr-details ndr-table tbody tr').click()`);await until(`document.querySelector('ndr-details dialog h2').textContent.includes('规则详情')`);
  await clickText('← 返回上一层');await until(`!!document.querySelector('.incident-heading')`);await shot('incident-desktop.png');await closeModal();
  await nav('drops');await until(`document.querySelector('ndr-events ndr-table tbody tr')?.textContent.includes('GPL') || document.querySelector('ndr-events').textContent.includes('阻断记录')`);
  await set('ndr-range select','yesterday','change');await until(`document.querySelector('ndr-events>section:last-of-type ndr-table tbody')?.textContent.includes('暂无数据')`);
  await set('ndr-range select','custom','change');await set('[aria-label="开始时间"]','2026-10-31T20:00');await set('[aria-label="结束时间"]','2026-10-30T20:00');await clickText('应用时间');await until(`document.querySelector('ndr-range .error')?.textContent.includes('开始时间')`);
  await clickText('重置');await until(`!document.querySelector('ndr-range .error')`);
  console.log('ok - incident investigation, nested rule details, drop ranges and invalid date rejection');

  await nav('hunt');await until(`document.querySelectorAll('ndr-events ndr-table tbody tr').length===8`);
  await set('[aria-label="搜索查询"]','flow:1001');await clickText('查询 →');await until(`document.querySelectorAll('ndr-events ndr-table tbody tr').length===6`);
  await set('[aria-label="搜索查询"]','unknown_field:bad');await clickText('查询 →');await until(`!!document.querySelector('ndr-events>.error')`);
  await set('[aria-label="搜索查询"]','');await clickText('查询 →');await until(`!document.querySelector('ndr-events>.error')`);
  await clickText('＋ 手动规则');await until(`!!document.querySelector('ndr-rule-editor dialog')`);
  await set('[formcontrolname="message"]','Angular guided fixture');await set('[aria-label="检测关键字"]','content');await set('[aria-label="条件值"]','angular.example');
  assert.equal(await evaluate(`document.querySelector('[data-testid="rule-preview"]').textContent.includes('content:"angular.example"')`),true);
  await clickText('＋ 条件');assert.equal(await evaluate(`document.querySelectorAll('.condition').length`),2);
  await set('[formcontrolname="sid"]','9900101');await clickText('保存并热重载');await until(`!document.querySelector('ndr-rule-editor')`);
  assert.equal((await api('/api/hunt/rules')).rules.some(r=>r.sid===9900101),true);
  console.log('ok - Angular query forms, syntax errors and guided rule creation with live preview');

  await nav('rules');await ruleTab('检测签名');await until(`document.querySelector('ndr-rules ndr-table tbody tr')?.textContent.includes('2100622')`);
  assert.equal(await evaluate(`document.querySelectorAll('ndr-rules .tabs button').length`),8);
  assert.equal(await evaluate(`document.querySelectorAll('ndr-rules ndr-table tbody tr').length`),50);
  await evaluate(`document.querySelector('ndr-rules ndr-table tbody input').click()`);
  await clickText('下一页 →',`document.querySelector('ndr-rules ndr-table')`);await until(`document.querySelector('ndr-rules ndr-table .pager')?.textContent.includes('2 / 3')`);
  await evaluate(`document.querySelector('ndr-rules ndr-table tbody input').click()`);await until(`document.querySelector('.selection-bar')?.textContent.includes('已选 2')`);
  await clickText('下一页 →',`document.querySelector('ndr-rules ndr-table')`);await until(`document.querySelector('ndr-rules ndr-table .pager')?.textContent.includes('3 / 3')`);
  assert.equal(await evaluate(`document.querySelectorAll('ndr-rules ndr-table tbody tr').length`),25);
  // Persist column sizes via the actual keyboard separator.
  await evaluate(`document.querySelector('ndr-rules ndr-table .resize').dispatchEvent(new KeyboardEvent('keydown',{key:'ArrowRight',bubbles:true}))`);
  assert.equal(await evaluate(`JSON.parse(localStorage.getItem('ndr.angular.columns.rules-catalog'))[0]`),120);
  await set('[aria-label="搜索规则签名"]','content');await clickText('搜索');await until(`document.querySelector('ndr-rules ndr-table .empty')?.textContent.includes('暂无数据')`);
  await set('[aria-label="搜索规则签名"]','sid:2100498');await clickText('搜索');await until(`document.querySelector('ndr-rules ndr-table tbody tr')?.textContent.includes('2100498')`);
  await ruleTab('禁用策略');await clickText('＋ 新建');await until(`document.querySelectorAll('ndr-picker tbody input').length===50`);
  await evaluate(`document.querySelector('ndr-picker tbody input').click()`);await clickText('下一页 →',`document.querySelector('ndr-picker ndr-table')`);await until(`document.querySelector('ndr-picker .pager').textContent.includes('2 / 3')`);
  await evaluate(`document.querySelector('ndr-picker tbody input').click()`);await clickText('确认保存');await until(`!document.querySelector('ndr-picker')`);
  assert.equal((await api('/api/rules/governance')).disable.length,2);
  await clickText('＋ 新建');await until(`document.querySelector('ndr-picker .pager')?.textContent.includes('123 条')`);await closeModal();assert.equal((await api('/api/rules/governance')).disable.length,2);
  console.log('ok - rule server pagination, cross-page selection, column persistence, duplicate filtering and cancellation');

  await ruleTab('阻断动作');await clickText('＋ 新建');await until(`document.querySelectorAll('ndr-picker tbody input').length>0`);await evaluate(`document.querySelector('ndr-picker tbody input').click()`);await set('[aria-label="目标动作"]','reject','change');await clickText('确认保存');await until(`!document.querySelector('ndr-picker')`);
  assert.equal((await api('/api/rules/governance')).action[0].action,'reject');
  await evaluate(`document.querySelector('ndr-rules ndr-table tbody input').click()`);await clickText('编辑');await until(`!!document.querySelector('ndr-picker')`);await set('[aria-label="目标动作"]','drop','change');await clickText('确认保存');await until(`!document.querySelector('ndr-picker')`);
  assert.equal((await api('/api/rules/governance')).action[0].action,'drop');
  await ruleTab('告警抑制');await clickText('＋ 新建');await until(`!!document.querySelector('ndr-picker')`);await set('[aria-label="选择对象类型"]','group','change');await until(`document.querySelector('ndr-picker tbody tr')?.textContent.includes('emerging-scan')`);
  await evaluate(`document.querySelector('ndr-picker tbody input').click()`);await clickText('确认保存');await until(`!document.querySelector('ndr-picker')`);
  assert.equal((await api('/api/rules/governance')).suppress_groups[0].total,125);
  assert.equal(await evaluate(`document.querySelectorAll('ndr-rules ndr-table tbody tr').length`),50);
  await clickText('下一页 →',`document.querySelector('ndr-rules ndr-table')`);await clickText('下一页 →',`document.querySelector('ndr-rules ndr-table')`);assert.equal(await evaluate(`document.querySelectorAll('ndr-rules ndr-table tbody tr').length`),25);
  await set('[aria-label="表格搜索"]','2100498');await until(`document.querySelectorAll('ndr-rules ndr-table tbody tr').length===1`);
  console.log('ok - action creation/editing and group suppression expanded to 125 SIDs with native client pagination');

  await ruleTab('手动规则');await until(`document.querySelector('ndr-rules ndr-table tbody').textContent.includes('9900101')`);await evaluate(`document.querySelector('ndr-rules ndr-table tbody input').click()`);await clickText('删除');await until(`document.querySelectorAll('dialog[open]').length===1`);await clickText('取消',`document.querySelector('dialog')`);assert.equal((await api('/api/hunt/rules')).rules.length,1);
  await clickText('删除');await clickText('确认',`document.querySelector('dialog')`);await until(`document.querySelector('ndr-rules ndr-table tbody').textContent.includes('暂无数据')`);
  await ruleTab('规则分组');await evaluate(`document.querySelector('ndr-rules ndr-table tbody tr').click()`);await until(`document.querySelector('ndr-rules dialog ndr-table .pager').textContent.includes('125 条')`);await closeModal();
  await ruleTab('封禁对象');await clickText('＋ 封禁');await until(`!!document.querySelector('[aria-label="封禁目标"]')`);await set('[aria-label="封禁目标"]','192.0.2.99');await clickText('确认封禁');await until(`!document.querySelector('ndr-rules dialog')`);assert.equal((await api('/api/rules')).bans.some(b=>b.value==='192.0.2.99'),true);
  await evaluate(`document.querySelector('ndr-rules ndr-table tbody input').click()`);await clickText('解封');await clickText('确认',`document.querySelector('dialog')`);await until(`document.querySelector('ndr-rules ndr-table tbody').textContent.includes('暂无数据')`);
  await ruleTab('规则源');await until(`!!document.querySelector('.schedule-form')`);await evaluate(`document.querySelector('input[name="enabled"]').click()`);await set('input[name="time"]','05:17');await clickText('保存计划');await until(`document.querySelector('ndr-rules').textContent.includes('下次执行')`);assert.equal((await api('/api/rules/schedule')).time,'05:17');
  await evaluate(`document.querySelector('input[name="enabled"]').click()`);await clickText('保存计划');await until(`document.querySelector('ndr-rules').textContent.includes('定时更新已关闭')`);
  console.log('ok - manual-rule deletion confirmation/cancel, group details, bans and schedule persistence');

  await shot('rules-desktop.png');await nav('system');await until(`document.querySelector('ndr-system').textContent.includes('65,000') || document.querySelector('ndr-system').textContent.includes('65000')`);await shot('system-desktop.png');
  // Browser-side transport fixtures test stale replies and failure preservation, never touch router state.
  await nav('rules');await ruleTab('检测签名');await until(`document.querySelector('ndr-rules ndr-table tbody tr')?.textContent.includes('2100622')`);
  await evaluate(`window.savedFetch=window.fetch; window.fetch=async(...args)=>{if(String(args[0]).includes('/api/rules/search'))throw new Error('offline fixture');return window.savedFetch(...args)}`);
  // HttpClient uses XMLHttpRequest; use CDP Fetch interception for real network failures.
  await evaluate(`window.fetch=window.savedFetch`);
  await cdp('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true});
  for(const page of ['overview','alerts','drops','hunt','rules','system']){await nav(page);await pause(300);assert.equal(await evaluate(`document.documentElement.scrollWidth<=innerWidth`),true,'mobile width: '+page);if(page==='overview'||page==='rules')await shot(page+'-mobile.png');}
  await cdp('Emulation.setDeviceMetricsOverride',{width:1440,height:1100,deviceScaleFactor:1,mobile:false});
  await nav('overview');await until(`!!document.querySelector('ndr-chart')`);
  await cdp('Network.emulateNetworkConditions',{offline:true,latency:0,downloadThroughput:0,uploadThroughput:0});await nav('rules');await until(`document.querySelector('ndr-rules>.error')?.textContent.includes('刷新失败')`);
  await cdp('Network.emulateNetworkConditions',{offline:false,latency:0,downloadThroughput:-1,uploadThroughput:-1});await clickText('↻ 刷新');await until(`document.querySelector('ndr-rules ndr-table tbody tr')?.textContent.includes('2100622')`);
  assert.deepEqual(exceptions,[],'no uncaught browser exceptions');
  await writeFile(path.join(screenshots,'browser-results.json'),JSON.stringify({ok:true,framework:'Angular 22.2.4',uncaughtExceptions:exceptions,mobileWidth:390,coverage:['overview','svg-chart','incident-detail','nested-rule','hunt','guided-rule','pagination','selection','column-widths','disable','action-edit','group-suppress','manual-delete','ban-unban','schedule','group-detail','system','six-page-mobile','network-recovery']},null,2));
  console.log('ok - six pages fit mobile, network failures recover, and no uncaught browser exceptions');
} finally {
  if(ws)ws.close();chrome.kill();await pause(500);
  const resolved=path.resolve(profile);assert.ok(resolved.startsWith(path.resolve(tmpdir())+path.sep)&&path.basename(resolved).startsWith('ndr-chrome-'));
  await rm(resolved,{recursive:true,force:true,maxRetries:5,retryDelay:200}).catch(()=>{});
}
