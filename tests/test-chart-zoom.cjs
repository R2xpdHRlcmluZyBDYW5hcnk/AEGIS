const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const ts=require('../frontend/node_modules/typescript'),echarts=require('../frontend/node_modules/echarts');
const compile=path=>ts.transpileModule(fs.readFileSync(path,'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS,experimentalDecorators:true}}).outputText;
const evaluate=(path,globals)=>new Function(...Object.keys(globals),compile(path))(...Object.values(globals));
const viewport={},options={};
evaluate('frontend/src/app/chart-viewport.ts',{exports:viewport});
evaluate('frontend/src/app/chart-options.ts',{exports:options});
const {ChartViewport}=viewport,points=Array.from({length:100},(_,i)=>({t:1700000000+60*i,alerts:i%7,drops:i%3}));
const shared=new ChartViewport(),full=shared.extent(points);
shared.set(points,full.from+600000,full.to-600000);const selected=shared.range(points);
assert.equal(shared.zoomed,true);
assert.equal(shared.range([...points.slice(1),{...points.at(-1),t:points.at(-1).t+60}]).from,selected.from,'live updates retain absolute visible time');
shared.set(points,full.from-100000,full.from+100000);assert.equal(shared.range(points).from,full.from);
shared.set(points,full.to-100000,full.to+100000);assert.equal(shared.range(points).to,full.to);
shared.range(points.map(p=>({...p,t:p.t+100000})));assert.equal(shared.zoomed,false,'unrelated intervals reset');
shared.set(points,full.from+600000,full.to-600000);shared.range(points.map((p,i)=>({...p,t:points[0].t+i*120})));assert.equal(shared.zoomed,false,'changed buckets reset');
shared.set(points,full.from,full.to);assert.equal(shared.zoomed,false);

class EventEmitter{values=[];emit(value){this.values.push(value);}}
const decorator=()=>value=>value,noop=()=>()=>{};
const angular={Component:decorator,Input:noop,Output:noop,ViewChild:noop,EventEmitter,ChangeDetectionStrategy:{Eager:0}};
const instances=[],observers=[];
class ResizeObserver{constructor(callback){this.callback=callback;observers.push(this);}observe(){}disconnect(){this.disconnected=true;}}
const exported={};
evaluate('frontend/src/app/chart.component.ts',{exports:exported,console,ResizeObserver,matchMedia:()=>({matches:true}),getComputedStyle:()=>({getPropertyValue:()=>''}),require:name=>name==='@angular/core'?angular:name==='./chart-viewport'?viewport:name==='./chart-options'?options:name==='./echarts-runtime'?{createChart(){const chart=echarts.init(null,null,{renderer:'svg',ssr:true,width:900,height:300});instances.push(chart);return chart;}}:{}});
async function component(shared=new ChartViewport(),ranks=null){
 const value=new exported.ChartComponent({run:fn=>fn(),runOutsideAngular:fn=>fn()},{markForCheck(){}});value.surface={nativeElement:{}};value.viewport=shared;value.points=points;value.ranks=ranks;await value.load();assert.equal(value.error,'','ECharts initializes without errors');return value;
}
(async()=>{
const normal=await component(shared),expanded=await component(shared),a=instances[0],b=instances[1];
try{
 const svg=a.renderToSVGString();assert.ok(svg.includes('<svg')&&svg.includes('<path'),'real ECharts renders chart geometry: '+svg.slice(0,600));
 assert.equal(a.getOption().series[0].itemStyle.color,'#35533b');assert.equal(a.getOption().series[1].itemStyle.color,'#724e26');
 const zoom=a.getOption().dataZoom[0];assert.equal(zoom.type,'inside');assert.equal(zoom.moveOnMouseMove,true);assert.equal(zoom.zoomOnMouseWheel,true);
 a.dispatchAction({type:'dataZoom',start:20,end:60});assert.equal(shared.zoomed,true);const before=shared.range(points);expanded.ngDoCheck();
 assert.ok(Math.abs(b.getOption().dataZoom[0].startValue-before.from)<1,'expanded chart receives native ECharts zoom');
 a.dispatchAction({type:'dataZoom',start:30,end:70});const moved=shared.range(points);assert.ok(moved.from>before.from);assert.equal(Math.round(moved.to-moved.from),Math.round(before.to-before.from),'native pan keeps the zoom span');
 normal.points=points.map(p=>({...p,alerts:p.alerts+10}));normal.ngOnChanges();assert.equal(a.getOption().dataZoom[0].startValue,moved.from,'refresh retains native zoom range');
 normal.resetZoom();expanded.ngDoCheck();assert.equal(shared.zoomed,false);assert.equal(b.getOption().dataZoom[0].startValue,full.from);
 const tooltip=a.getOption().tooltip[0];assert.equal(tooltip.confine,true);const html=tooltip.formatter([{value:[points[0].t*1000,4],seriesName:'告警',marker:''},{value:[points[0].t*1000,2],seriesName:'阻断',marker:''}]);assert.ok(html.includes('告警')&&html.includes('阻断')&&html.includes('4'));
 assert.equal(tooltip.transitionDuration,0);assert.equal(tooltip.displayTransition,false);assert.equal(tooltip.hideDelay,0);assert.equal(tooltip.axisPointer.animation,false);
 const zeroChart=await component(),z=instances.at(-1);
 const zeroPoints=[{t:points[0].t,alerts:0,drops:0},{t:points[1].t,alerts:4,drops:0},{t:points[2].t,alerts:0,drops:3}];
 zeroChart.points=zeroPoints;zeroChart.ngOnChanges();
 for(const [seriesIndex,key] of [[0,'alerts'],[1,'drops']]){
  const data=z.getModel().getSeriesByIndex(seriesIndex).getData();
  for(let index=0;index<zeroPoints.length;index++){
   const element=data.getItemGraphicEl(index);assert.ok(element);
   if(zeroPoints[index][key]===0){assert.equal(element.style.opacity,0,'zero buckets have no visible fill or stroke');assert.equal(element.style.lineWidth,0);}
   else{assert.notEqual(element.style.opacity,0);assert.ok(Math.abs(element.shape.height)>0,'positive counts remain visible');}
  }
 }
 z.dispatchAction({type:'highlight',seriesIndex:1,dataIndex:0});assert.equal(z.getModel().getSeriesByIndex(1).getData().getItemGraphicEl(0).style.opacity,0,'highlight cannot reveal a zero bucket');
 const zeroHtml=z.getOption().tooltip[0].formatter([{value:[zeroPoints[0].t*1000,0],seriesName:'告警',marker:''},{value:[zeroPoints[0].t*1000,0],seriesName:'阻断',marker:''}]);assert.equal((zeroHtml.match(/<strong>0<\/strong>/g)||[]).length,2,'tooltips retain both zero values');
 zeroChart.points=zeroPoints.map(point=>({...point,alerts:0,drops:0}));zeroChart.ngOnChanges();
 for(let seriesIndex=0;seriesIndex<2;seriesIndex++){const data=z.getModel().getSeriesByIndex(seriesIndex).getData();for(let index=0;index<zeroPoints.length;index++)assert.equal(data.getItemGraphicEl(index).style.opacity,0,'refresh clears formerly positive bars');}
 zeroChart.points=zeroPoints;zeroChart.ngOnChanges();
 assert.notEqual(z.getModel().getSeriesByIndex(0).getData().getItemGraphicEl(1).style.opacity,0,'a formerly zero alert bucket becomes visible when events arrive');
 assert.notEqual(z.getModel().getSeriesByIndex(1).getData().getItemGraphicEl(2).style.opacity,0,'a formerly zero drop bucket becomes visible when events arrive');
 zeroChart.ngOnDestroy();
 // Dispatch through zrender's real input handlers, without reimplementing gestures.
 const handler=a.getZr().handler;
 if(handler){
  const input=(x=450)=>({zrX:x,zrY:120,button:0,which:1,preventDefault(){},stopPropagation(){}});
  handler.dispatch('mousewheel',{...input(),zrDelta:1});await new Promise(resolve=>setTimeout(resolve,80));assert.equal(shared.zoomed,true,'ECharts handles wheel input');
  const wheelFrom=shared.range(points).from;handler.dispatch('mousedown',input());handler.dispatch('mousemove',input(550));handler.dispatch('mouseup',input(550));await new Promise(resolve=>setTimeout(resolve,80));assert.ok(shared.range(points).from<wheelFrom,'ECharts handles drag panning after wheel zoom');
 }
 const ranked=await component(new ChartViewport(),[{sig:'<img src=x onerror=alert(1)>',count:7}]),c=instances.at(-1);
 const rankTooltip=c.getOption().tooltip[0].formatter({dataIndex:0,value:7});assert.ok(rankTooltip.includes('&lt;img')&&!rankTooltip.includes('<img'),'untrusted event labels cannot create HTML');
 assert.equal(c.getOption().tooltip[0].transitionDuration,0,'rank tooltips use the same immediate hover behavior');
 c.trigger('click',{componentType:'series',dataIndex:0});assert.equal(ranked.rowOpen.values[0].count,7,'rank clicks preserve investigation records');ranked.ngOnDestroy();
 normal.openItem({componentType:'series',dataIndex:1,seriesId:'alerts'});
 assert.equal(normal.pointOpen.values[0].point.t,points[1].t);assert.equal(normal.pointOpen.values[0].kind,'alerts');
 normal.openItem({componentType:'xAxis',dataIndex:1,seriesId:'alerts'});
 normal.openItem({componentType:'series',dataIndex:-1,seriesId:'drops'});
 assert.equal(normal.pointOpen.values.length,1,'axes and missing points cannot filter the overview');
 normal.points=[];normal.ngOnChanges();assert.ok(a.renderToSVGString().includes('<svg'),'empty periods render safely');
 normal.ngOnDestroy();expanded.ngOnDestroy();assert.ok(instances.every(chart=>chart.isDisposed()));assert.ok(observers.every(observer=>observer.disconnected));
 console.log('ok - real ECharts rendering, native zoom/pan, shared range, live refresh, rank clicks, tooltip escaping and lifecycle cleanup');
}finally{for(const chart of instances)if(!chart.isDisposed())chart.dispose();}
})().catch(error=>{console.error(error);process.exitCode=1;});
