import {testOutput} from './test-output.mjs';
// Browser workflow checks launched by tests/run_browser_regression.py.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, writeFile, mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
const profile = await mkdtemp(path.join(tmpdir(), 'ndr-chrome-'));
const chromePath = process.env.CHROME_PATH || 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const chrome = spawn(chromePath, ['--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check', '--remote-debugging-port=0', '--remote-allow-origins=*', `--user-data-dir=${profile}`, 'about:blank'], { windowsHide: true, stdio: 'ignore' });
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
let ws,holdOverview=false,heldDbStats,clearRequests=0;
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
      if(message.params.request.url.endsWith('/api/db/stats'))heldDbStats=message.params.requestId;
      else if(holdOverview)heldOverview.push(message.params.requestId);
      else void cdp('Fetch.continueRequest',{requestId:message.params.requestId}).catch(()=>{});
      return;
    }
    if(message.method==='Network.requestWillBeSent'&&message.params.request.url.endsWith('/api/db/clear')&&message.params.request.method==='POST')clearRequests++;
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
  // This key can still hold the initial prewarm snapshot while the UI uses a
  // different time-window key. Ingestion intentionally preserves both snapshots
  // until their background refresh completes.
  let overview;
  for(let i=0;i<100;i++){overview=await api('/api/overview?scope=cache&view=panel');if(overview.security.alerts===3)break;await pause(100);}
  assert.equal(overview.security.alerts,3);assert.equal(overview.security.high,1);assert.equal(overview.security.drops,2);
  assert.deepEqual(overview.series.reduce((sum,p)=>[sum[0]+p.alerts,sum[1]+p.drops],[0,0]),[3,2],'alert trend excludes suppression and block trend retains enforcement');
  assert.ok(overview.top.signatures.length>0&&overview.top.signatures.every(r=>!r.sig.includes('suppressed')),'signature ranks exclude suppressed records');
  await clickText('表格',`document.querySelector('ndr-overview .three-grid section:nth-child(2)')`);
  await until(`[...document.querySelectorAll('ndr-overview .three-grid section:nth-child(2) ndr-table tbody tr')].some(r=>r.textContent.includes('192.0.2.20'))`);
  await holdOverviewRequests();
  await evaluate(`[...document.querySelectorAll('ndr-overview .three-grid section:nth-child(2) ndr-table tbody tr')].find(r=>r.textContent.includes('192.0.2.20')).click()`);
  await until(`document.querySelector('ndr-overview ndr-table#recent .table-scroll')?.getAttribute('aria-busy')==='true'`);
  assert.equal(await evaluate(`document.querySelectorAll('ndr-overview ndr-table#recent tbody tr[tabindex]').length`),0,'changing filters hides logs from the previous selection while loading');
  await releaseOverviewRequests();
  await until(`document.querySelector('ndr-overview ndr-table#recent .table-scroll')?.getAttribute('aria-busy')==='false'&&document.querySelectorAll('ndr-overview ndr-table#recent tbody tr[tabindex]').length===1`);
  assert.equal(await evaluate(`document.querySelector('ndr-overview ndr-table#recent tbody').textContent.includes('192.0.2.20')`),true,'overview source filter applies to latest logs');
  assert.equal(await evaluate(`document.querySelector('[data-testid="alerts-total"]').textContent.trim()`),'0','statistics use the same source filter as logs');
  await clickText('清除筛选',`document.querySelector('ndr-overview')`);
  await until(`document.querySelector('[data-testid="alerts-total"]')?.textContent.trim()==='3'&&document.querySelectorAll('ndr-overview ndr-table#recent tbody tr[tabindex]').length===10`);
  await until(`!!document.querySelector('ndr-chart .echarts-surface svg')`);
  await shot('go-overview-desktop.png');
  await cdp('Fetch.enable',{patterns:[{urlPattern:'*/api/db/stats',requestStage:'Request'}]});
  await nav('system');
  await until(`document.querySelector('.database-card button')?.textContent.trim()==='清空历史事件' && !!document.querySelector('#db-capacity')`);
  for(let i=0;!heldDbStats&&i<100;i++)await pause(50);
  assert.ok(heldDbStats,'the clear action renders while the statistics request is still pending');
  const databaseCard=`document.querySelector('.database-card')`;
  const databaseValues=`[...${databaseCard}.querySelectorAll('dl dd')].map(node=>node.textContent.trim())`;
  assert.deepEqual(await evaluate(`[...${databaseCard}.querySelectorAll('dl dt')].map(node=>node.textContent.trim())`),
    ['文件','大小 / 上限','事件数','最早事件','最新事件'],'database fields are present during loading');
  const loadingValues=await evaluate(databaseValues);
  assert.match(loadingValues[1],/^读取中… \/ \d+(?:\.\d+)? [A-Za-z]+$/,'capacity is displayed before usage is available');
  assert.deepEqual([loadingValues[0],...loadingValues.slice(2)],Array(4).fill('读取中…'));
  await clickText('清空历史事件',databaseCard);
  await until(`document.querySelector('dialog[open]')?.textContent.includes('尚未入库的原始日志')`);
  await cdp('Input.dispatchKeyEvent',{type:'keyDown',key:'Escape',code:'Escape',windowsVirtualKeyCode:27});
  await cdp('Input.dispatchKeyEvent',{type:'keyUp',key:'Escape',code:'Escape',windowsVirtualKeyCode:27});
  await until(`!document.querySelector('dialog[open]')`);
  assert.equal(clearRequests,0,'dismissing the confirmation does not clear history');
  const initialCapacity=(await api('/api/db/settings')).cap/1048576;
  await set('.db-capacity select','MiB','change');
  await until(`Number(document.querySelector('#db-capacity')?.value)===${initialCapacity}`);
  await set('#db-capacity',initialCapacity-1);
  await clickText('保存',databaseCard);
  await until(`document.querySelector('dialog[open]')?.textContent.includes('当前占用暂不可用')`);
  await clickText('取消',`document.querySelector('dialog[open]')`);
  assert.equal((await api('/api/db/settings')).cap,initialCapacity*1048576,'cancelling a lower capacity preserves settings');
  await cdp('Fetch.fulfillRequest',{
    requestId:heldDbStats,responseCode:503,responseHeaders:[{name:'Content-Type',value:'application/json'}],
    body:Buffer.from(JSON.stringify({error:'fixture statistics unavailable'})).toString('base64'),
  });
  await cdp('Fetch.disable');
  await until(`document.querySelector('.database-card [role="alert"]')?.textContent.includes('无法读取事件库统计')`);
  assert.deepEqual(await evaluate(databaseValues),loadingValues.map(value=>value.replace('读取中…','未读取')),
    'failed statistics retain each field and replace its loading placeholder');
  const savedCapacity=initialCapacity+1;
  await set('#db-capacity',savedCapacity);
  await clickText('保存',databaseCard);
  await until(`document.querySelector('.toast')?.textContent.includes('容量上限已保存')`);
  assert.equal((await api('/api/db/settings')).cap,savedCapacity*1048576,'capacity saves even when statistics fail');
  await clickText('清空历史事件',databaseCard);
  await clickText('确认',`document.querySelector('dialog[open]')`);
  // The real manager refuses history maintenance outside the installed layout.
  await until(`document.querySelector('.toast')?.textContent.includes('历史维护只支持独立服务布局')`);
  assert.equal(clearRequests,1,'the confirmed action reaches the backend even after statistics fail');
  await until(`!document.querySelector('.database-card button')?.disabled`);
  await holdOverviewRequests();await nav('overview');
  await until(`document.querySelector('[data-testid="alerts-total"]')?.textContent.trim()==='3'`);
  assert.equal(await evaluate(`!!document.querySelector('[data-testid="overview-loading"]')`),false,'returning overview retains its snapshot while requests are held');
  assert.equal(await evaluate(`!!document.querySelector('ndr-overview>[role="status"]:not(.overview-loading)')`),false,'refreshing a retained snapshot adds no status text');
  await releaseOverviewRequests();
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
  for(const [width,height] of [[1280,800],[1440,1100],[1920,1080]]){
    await cdp('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:false});
    assert.deepEqual(await evaluate(`(()=>{
      const summary=document.querySelector('.rule-status-grid').getBoundingClientRect(),list=document.querySelector('.rules-list').getBoundingClientRect(),tabs=document.querySelector('ndr-rules .tabs'),actions=document.querySelector('.rule-actions'),t=tabs.getBoundingClientRect(),a=actions.getBoundingClientRect(),buttons=[...actions.querySelectorAll('button')],style=buttons.map(e=>getComputedStyle(e));
      return {fullWidth:Math.abs(summary.left-list.left)<1&&Math.abs(summary.right-list.right)<1,rightAligned:Math.abs(a.right-list.right)<1,centered:Math.abs(t.y+t.height/2-a.y-a.height/2)<1,sameFont:style.every(s=>s.fontSize===getComputedStyle(tabs.querySelector('button')).fontSize&&s.lineHeight==='20px'),sameHeight:buttons.every(e=>e.getBoundingClientRect().height===38),outsideTablist:!actions.closest('[role=tablist]'),noOverlap:t.right<=a.left,noOverflow:document.documentElement.scrollWidth<=innerWidth};
    })()`),{fullWidth:true,rightAligned:true,centered:true,sameFont:true,sameHeight:true,outsideTablist:true,noOverlap:true,noOverflow:true},'rule summary, tabs and actions align at '+width);
    if(process.env.AEGIS_RULE_SCREENSHOT){const {data}=await cdp('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});await writeFile(process.env.AEGIS_RULE_SCREENSHOT.replace('.png','-'+width+'.png'),Buffer.from(data,'base64'));}
  }
  await cdp('Emulation.setDeviceMetricsOverride',{width:1440,height:1100,deviceScaleFactor:1,mobile:false});
  await evaluate(`document.querySelector('ndr-rules [role=tab][aria-selected=true]').focus()`);
  await cdp('Input.dispatchKeyEvent',{type:'keyDown',key:'ArrowRight',code:'ArrowRight'});await cdp('Input.dispatchKeyEvent',{type:'keyUp',key:'ArrowRight',code:'ArrowRight'});
  await until(`document.activeElement?.id==='rule-tab-groups'&&document.activeElement?.getAttribute('aria-selected')==='true'`);
  await ruleTab('检测签名');
  await clickText('↻ 刷新',`document.querySelector('.rule-actions')`);
  await clickText('下一页 →',`document.querySelector('ndr-rules ndr-table')`);await until(`document.querySelector('ndr-rules .pager')?.textContent.includes('2 / 3')`);
  await ruleTab('禁用策略');await clickText('＋ 新建');await until(`document.querySelectorAll('ndr-picker tbody input').length===50`);
  await evaluate(`document.querySelector('ndr-picker tbody input').click()`);await clickText('确认保存');await until(`!document.querySelector('ndr-picker')`);
  const disabledPolicy=(await api('/api/rules/governance')).disable;assert.equal(disabledPolicy.length,1);
  assert.ok(disabledPolicy[0].name.startsWith('Fixture signature '),'disabled policies resolve a signature description');
  await until(`document.querySelector('ndr-rules tbody')?.textContent.includes(${JSON.stringify(disabledPolicy[0].name)})`);
  const groups=(await api('/api/rules/groups')).groups;assert.ok(groups.some(g=>g.total===125));
  await ruleTab('规则分组');await until(`document.querySelector('ndr-rules tbody')?.textContent.includes('snort/community')`);
  const group=groups.find(g=>g.total===125);assert.equal((await api('/api/rules/suppress-groups','POST',{groups:[group.selector]})).ok,true);
  assert.equal((await api('/api/rules/governance')).suppress_groups[0].total,125);
  assert.equal((await api('/api/hunt/rules','POST',{rule:'alert tcp any any -> any 443 (msg:"Browser fixture"; sid:9900101; rev:1;)'})).ok,true);
  assert.ok((await api('/api/hunt/rules')).rules.some(r=>r.sid===9900101));
  assert.equal((await api('/api/bans','POST',{target:'192.0.2.99'})).ok,true);
  const schedule=await api('/api/rules/schedule','POST',{enabled:true,frequency:'weekly',time:'05:17',weekday:0});assert.equal(schedule.time,'05:17');assert.ok(schedule.next_run>0);
  await api('/api/rules/pending/discard','POST');assert.equal((await api('/api/actions/status')).pending,false);
  await ruleTab('规则源');
  async function configureOfficial(name){
    await evaluate(`(()=>{const row=[...document.querySelectorAll('ndr-rules tbody tr')].find(r=>r.textContent.includes(${JSON.stringify(name)}));if(!row)throw Error('Official source missing');const box=row.querySelector('input[type="checkbox"]');if(!box.checked)box.click();})()`);
    await clickText('配置规则源');await until(`!!document.querySelector('ndr-source-editor select[name="ips_policy"]')`);
  }
  await configureOfficial('snort/lightspd');
  assert.deepEqual(await evaluate(`[...document.querySelector('select[name="ips_policy"]').options].map(o=>o.value)`),['connectivity','balanced','security','max-detect']);
  await set('select[name="ips_policy"]','max-detect','change');await clickText('保存',`document.querySelector('ndr-source-editor')`);await until(`!document.querySelector('ndr-source-editor')`);
  assert.ok((await api('/api/rules/sources')).sources.filter(r=>r.requires_code).every(r=>r.ips_policy==='max-detect'));
  await until(`document.querySelector('ndr-rules tbody')?.textContent.includes('max-detect 最大检测覆盖')`);
  await configureOfficial('snort/registered');assert.equal(await evaluate(`document.querySelector('select[name="ips_policy"]').value`),'max-detect');
  await pause(450);
  assert.equal(await evaluate(`(()=>{const a=document.querySelector('ndr-source-editor input[name="oinkcode"]').getBoundingClientRect(),b=document.querySelector('select[name="ips_policy"]').getBoundingClientRect();return Math.abs(a.x-b.x)<1&&Math.abs(a.width-b.width)<1;})()`),true,'source controls align and fill the form');
  await evaluate(`document.querySelector('select[name="ips_policy"]').focus()`);
  for(const key of ['Home','End']){await cdp('Input.dispatchKeyEvent',{type:'keyDown',key,code:key});await cdp('Input.dispatchKeyEvent',{type:'keyUp',key,code:key});await until(`document.querySelector('select[name="ips_policy"]').value==='${key==='Home'?'connectivity':'max-detect'}'`);}
  await shot('go-source-policy-desktop.png');await closeModal();
  await api('/api/rules/pending/discard','POST');await clickText('↻ 刷新');
  assert.ok((await api('/api/rules/sources')).sources.filter(r=>r.requires_code).every(r=>r.ips_policy==='balanced'));
  await api('/api/rules/source/config','POST',{name:'snort/lightspd',ips_policy:'security'});
  await api('/api/rules/disable','POST',{value:'sid:2100100'});
  await api('/api/rules/action','POST',{selector:'sid:2100101',action:'reject'});
  await api('/api/rules/suppress','POST',{sids:['2100102']});
  await api('/api/hunt/rules','POST',{rule:'alert tcp any any -> any 443 (msg:"Updated manual fixture"; sid:9900102; rev:1;)'});
  await api('/api/hunt/rules','POST',{rule:'alert tcp any any -> any 443 (msg:"Additional updated signature"; sid:9900103; rev:1;)'});
  await api('/api/bans','POST',{target:'192.0.2.99'});
  await clickText('↻ 刷新');await until(`!!document.querySelector('.pending-rules')`);
  const enabledSignatures=`Number(document.querySelector('.rule-status-card strong')?.textContent.replaceAll(',',''))`;
  assert.equal(await evaluate(`document.querySelector('.rule-status-card span')?.textContent.trim()`),'启用签名数');
  const beforeUpdate=await evaluate(enabledSignatures);
  assert.equal(beforeUpdate,125,'pending edits do not change the count of enabled signatures');
  assert.equal(await evaluate(`document.querySelector('ndr-rules').textContent.includes('再点击“应用更改”启用')`),false,'source hint matches automatic update application');
  await evaluate(`window.__jobLogWarnings=[];window.__jobLogObserver=new MutationObserver(()=>{if(document.querySelector('ndr-rules')?.textContent.includes('操作日志更新失败'))window.__jobLogWarnings.push(true);});window.__jobLogObserver.observe(document.querySelector('ndr-rules'),{subtree:true,childList:true,characterData:true});`);
  await clickText('更新规则集 ↗');
  await until(`document.querySelector('ndr-rules .tabs button.active')?.textContent.trim()==='操作日志'`);
  await until(`document.querySelector('ndr-rules .job-log')?.textContent.includes('规则已校验并完成热重载')&&!document.querySelector('.pending-rules')`);
  const updated=await api('/api/actions/status');assert.equal(updated.rc,0);assert.equal(updated.pending,false);assert.ok(updated.log_bytes>0);
  await until(`${enabledSignatures}>${beforeUpdate}`);
  const afterUpdate=await evaluate(enabledSignatures);
  assert.equal((await api('/api/rules/governance')).disable.length,1);
  assert.ok((await api('/api/hunt/rules')).rules.some(r=>r.sid===9900102));
  assert.ok((await api('/api/rules/sources')).sources.filter(r=>r.requires_code).every(r=>r.ips_policy==='security'));
  await api('/api/rules/action','POST',{selector:'sid:2100103',action:'drop'});
  await api('/api/hunt/rules','POST',{rule:'alert tcp any any -> any 443 (msg:"Additional applied signature"; sid:9900104; rev:1;)'});
  await clickText('应用更改 →');
  await until(`(async()=>{const r=await fetch('/api/actions/status').then(r=>r.json());return r.id!==${JSON.stringify(updated.id)}&&r.state==='done'&&r.rc===0&&!r.pending;})()`);
  await until(`!document.querySelector('.pending-rules')&&document.querySelector('ndr-rules .job-log')?.textContent.includes('规则已校验并完成热重载')`);
  await until(`${enabledSignatures}===${afterUpdate+1}`);
  await evaluate(`window.__jobLogObserver.disconnect()`);assert.deepEqual(await evaluate(`window.__jobLogWarnings`),[],'starting update and apply jobs does not flash a log-read error');
  await shot('go-rules-desktop.png');
  await nav('system');
  await until(`Number(document.querySelector('#db-capacity')?.value)===${savedCapacity/1024}
    && (${databaseValues}).length===5 && (${databaseValues}).every(value=>value&&!/读取中|未读取/.test(value))`);
  await shot('go-system-desktop.png');
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
