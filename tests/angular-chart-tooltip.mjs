// Chart interaction checks against the local Go preview started by preview.py.
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


  await evaluate(`document.querySelector('.trend ndr-chart').scrollIntoView({block:'center'})`);
  await until(`!!document.querySelector('.trend .echarts-surface svg')`);
  const point=await evaluate(`(()=>{const r=document.querySelector('.trend .echarts-surface').getBoundingClientRect();return {x:r.x+r.width*.6,y:r.y+r.height*.5}})()`);
  await cdp('Input.dispatchMouseEvent',{type:'mouseMoved',...point});
  await until(`!!document.querySelector('.trend .echarts-tooltip') && document.querySelector('.trend .echarts-tooltip').textContent.includes('告警')`);
  const tip=await evaluate(`(()=>{const t=document.querySelector('.trend .echarts-tooltip').getBoundingClientRect(),c=document.querySelector('.trend .echarts-surface').getBoundingClientRect();return {left:t.left,right:t.right,top:t.top,bottom:t.bottom,cl:c.left,cr:c.right,ct:c.top,cb:c.bottom,text:document.querySelector('.trend .echarts-tooltip').textContent}})()`);
  assert.ok(tip.left>=tip.cl&&tip.right<=tip.cr&&tip.top>=tip.ct&&tip.bottom<=tip.cb,'native ECharts tooltip remains inside the chart');
  assert.ok(tip.text.includes('告警')&&tip.text.includes('阻断'));
  const tooltipStyle=()=>evaluate(`(()=>{const e=document.querySelector('.trend .echarts-tooltip'),s=getComputedStyle(e);return {transition:s.transitionProperty,duration:s.transitionDuration,willChange:s.willChange,visible:document.querySelectorAll('.trend .echarts-tooltip').length}})()`);
  const before=await tooltipStyle();
  if(process.env.NDR_TOOLTIP_BASELINE==='1')console.log('Baseline tooltip style: '+JSON.stringify(before));
  else{
   assert.ok(before.duration.split(',').every(value=>parseFloat(value)===0),'hover tooltip position has no trailing transition');
   assert.equal(before.willChange,'auto','hover tooltip does not force a separate transform layer');
  }
  const surface=await evaluate(`(()=>{const r=document.querySelector('.trend .echarts-surface').getBoundingClientRect();return {left:r.left,right:r.right,top:r.top,height:r.height}})()`);
  for(const x of [surface.left+70,surface.right-40,surface.left+120,surface.right-80]){
   await cdp('Input.dispatchMouseEvent',{type:'mouseMoved',x,y:surface.top+surface.height*.5});
   await evaluate(`new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))`);
   assert.equal((await tooltipStyle()).visible,1,'rapid hover reuses one tooltip instance');
   if(process.env.NDR_TOOLTIP_BASELINE==='1')console.log('Baseline moving tooltip style: '+JSON.stringify(await tooltipStyle()));
   else assert.ok((await tooltipStyle()).duration.split(',').every(value=>parseFloat(value)===0),'rapid pointer movement never starts a tooltip transition');
  }
  await cdp('Input.dispatchMouseEvent',{type:'mouseMoved',x:surface.left+20,y:surface.top-10});
  await until(`(()=>{const e=document.querySelector('.trend .echarts-tooltip'),s=getComputedStyle(e);return s.display==='none'||s.visibility==='hidden'})()`);
  await cdp('Input.dispatchMouseEvent',{type:'mouseMoved',...point});
  await until(`getComputedStyle(document.querySelector('.trend .echarts-tooltip')).display!=='none'`);
  await cdp('Input.dispatchMouseEvent',{type:'mouseWheel',...point,deltaX:0,deltaY:-600});
  await until(`!!document.querySelector('.trend .chart-zoom-reset')`);
  const ticks=()=>evaluate(`[...document.querySelectorAll('.trend .echarts-surface svg text')].filter(e=>/^\\d{2}:\\d{2}$/.test(e.textContent)).map(e=>({text:e.textContent,x:e.getBoundingClientRect().x,y:e.getBoundingClientRect().y}))`);
  const zoomed=await ticks();
  await cdp('Input.dispatchMouseEvent',{type:'mousePressed',...point,button:'left',clickCount:1});
  await cdp('Input.dispatchMouseEvent',{type:'mouseMoved',x:point.x+140,y:point.y,button:'left',buttons:1});
  await cdp('Input.dispatchMouseEvent',{type:'mouseReleased',x:point.x+140,y:point.y,button:'left',clickCount:1});
  await pause(250);assert.notDeepEqual(await ticks(),zoomed,'native drag changes time labels or their positions');
  await pointerClick('.trend .chart-zoom-reset');
  await until(`!document.querySelector('.trend .chart-zoom-reset')`);
  await pointerClick('.trend button[aria-label="放大告警与阻断趋势"]');
  await until(`!!document.querySelector('dialog .echarts-surface svg')`);
  const expanded=await evaluate(`(()=>{const r=document.querySelector('dialog .echarts-surface').getBoundingClientRect();return {x:r.x+r.width*.6,y:r.y+r.height*.5}})()`);
  await cdp('Input.dispatchMouseEvent',{type:'mouseMoved',...expanded});
  await until(`!!document.querySelector('dialog .echarts-tooltip')?.textContent.includes('告警')`);
  if(process.env.NDR_TOOLTIP_BASELINE!=='1')assert.equal(await evaluate(`getComputedStyle(document.querySelector('dialog .echarts-tooltip')).transitionDuration`),'0s','expanded tooltip also follows immediately');
  assert.deepEqual(exceptions,[]);
  console.log('ok - rapid hover uses one tooltip, immediate hide, wheel zoom, drag pan, reset and expanded chart');
} finally {
 if(ws)ws.close();chrome.kill();await pause(500);const resolved=path.resolve(profile);assert.ok(resolved.startsWith(path.resolve(tmpdir())+path.sep)&&path.basename(resolved).startsWith('ndr-chrome-'));await rm(resolved,{recursive:true,force:true,maxRetries:5,retryDelay:200}).catch(()=>{});
}
