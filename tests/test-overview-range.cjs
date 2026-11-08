const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const ts=require('../frontend/node_modules/typescript');
const compile=path=>ts.transpileModule(fs.readFileSync(path,'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS,experimentalDecorators:true}}).outputText;
const decorator=()=>value=>value;
const angular={Component:decorator,Injectable:decorator,ChangeDetectionStrategy:{Eager:0}};
const core={};
vm.runInNewContext(compile('frontend/src/app/core.ts'),{exports:core,require:name=>name==='@angular/core'?angular:{}});
const viewport={};vm.runInNewContext(compile('frontend/src/app/chart-viewport.ts'),{exports:viewport});
const key='ndr.angular.overview.range';
function fixture(storage=new Map(),views=new Map()){
 const requests=[],investigations=[],contexts=[];
 let receive;
 class LiveQuery {constructor(api,callback){receive=callback;}start(path,params,topic){requests.push({path,params,topic});}stop(){}}
 const exported={};
 vm.runInNewContext(compile('frontend/src/app/pages/overview.component.ts'),{exports:exported,require:name=>name==='@angular/core'?angular:name==='../chart-viewport'?viewport:name==='../core'?{...core,LiveQuery}:{},localStorage:{getItem:name=>storage.get(name)??null,setItem:(name,value)=>storage.set(name,value)}});
 return {page:new exported.OverviewComponent({}, {views,viewReady(){},investigate:(query,ts,range)=>{investigations.push(query);contexts.push(range&&JSON.parse(JSON.stringify(range)));}}, {}),requests,storage,investigations,contexts,deliver:data=>receive(data),views};
}
{
 const views=new Map(),first=fixture(new Map(),views);first.page.ngOnInit();
 assert.equal(first.page.data,undefined);assert.equal(first.page.refreshing,true);
 first.deliver({security:{alerts:7},range:[100,200]});first.page.filterKind('alerts','检测告警');
 first.deliver({security:{alerts:5},range:[100,200]});first.page.ngOnDestroy();
 const next=fixture(new Map(),views);next.page.ngOnInit();
 assert.equal(next.page.data.security.alerts,5,'returning overview immediately retains the previous snapshot');
 assert.equal(next.requests[0].params.detection,'alerts','returning overview keeps matching filter context');
 assert.equal(next.page.filterPending,false);assert.equal(next.page.showingPrevious,true);
 next.page.filterKind('high','高危告警');next.page.ngOnDestroy();
 const pending=fixture(new Map(),views);pending.page.ngOnInit();
 assert.equal(pending.page.data.security.alerts,5);assert.equal(pending.page.filterPending,true,'old values stay marked when the selected filter has not returned yet');
 pending.deliver({security:{alerts:1},range:[100,200]});assert.equal(pending.page.showingPrevious,false);assert.equal(pending.page.refreshing,false);
}
{
 const {page}=fixture();
 assert.equal(page.networkRetrying({error:'网络统计更新失败：网络统计计算超时',retry_seconds:5}),true);
 assert.equal(page.networkRetrying({error:'事件库不可用',retry_seconds:5}),false);
}
{
 const {page,investigations}=fixture();
 page.investigateTop({key:'signatures'},{sid:2021076});
 page.investigateTop({key:'signatures'},{sig:'engine drop: flow drop'});
 page.investigateTop({key:'sources',field:'src'},{ip:'2001:db8::1'});
 assert.deepEqual(investigations,['sid: 2021076','type: drop AND sig: "engine drop: flow drop"','src: "2001:db8::1"']);
}
{
 const {page,requests,storage,contexts}=fixture(new Map([[key,JSON.stringify({choice:'custom',from:'2026-10-01T09:00',to:'2026-10-02T09:00'})]]));
 page.ngOnInit();
 assert.deepEqual(JSON.parse(JSON.stringify(requests[0])),{path:'/api/overview',params:{scope:'cache',view:'panel'},topic:'overview'});
 page.data={range:[1793491200.123,1793491301.456]};
 page.investigate('type: alert AND level: high');
 assert.equal(contexts[0].choice,'custom');
 assert.deepEqual([+new Date(contexts[0].from),+new Date(contexts[0].to)],[1793491200123,1793491301456]);
 assert.deepEqual([...storage.keys()],[key],'legacy range preferences are ignored');
}
{
 const {page,requests,investigations}=fixture();page.ngOnInit();
 page.filterKind('alerts','检测告警');assert.equal(requests.at(-1).params.detection,'alerts');assert.equal(requests.at(-1).params.scope,'cache');
 page.filterTop({key:'sources',field:'src'},{ip:'2001:db8::1'});assert.equal(requests.at(-1).params.src,'2001:db8::1');
 page.filterKind('high','高危告警');assert.equal(requests.at(-1).params.detection,'high');assert.equal(page.filters.filter(f=>f.key==='kind').length,1);
 page.filterTop({key:'signatures'},{sid:498});assert.equal(requests.at(-1).params.sid,'498');
 page.removeFilter('src');assert.equal(requests.at(-1).params.src,undefined);assert.equal(requests.at(-1).params.sid,'498');
 assert.equal(investigations.length,0,'numeric and chart filters stay in overview');
 page.clearFilters();assert.equal(page.filters.length,0);assert.equal(requests.at(-1).params.detection,undefined);
 page.filterNetwork({title:'应用',field:'app',type:'flow'},{name:'未识别'});assert.equal(requests.at(-1).params.missing_app,'1');assert.equal(requests.at(-1).params.type,undefined,'application filters retain the complete connection cohort');
 page.investigateNetwork({field:'app',type:'flow'},{name:'tls'});assert.equal(investigations.at(-1),'type: flow AND app: "tls"','text table keeps investigation navigation');
 page.clearFilters();const t=Math.floor(Date.now()/1000)-120;page.data={bucket:1,range:[t,t+90]};
 page.filterTrend({point:{t},kind:'drops'});assert.equal(requests.at(-1).params.from,String(t));assert.equal(requests.at(-1).params.to,String(t+60-.001));
 assert.equal(requests.at(-1).params.detection,'drops');page.removeFilter('period');assert.equal(requests.at(-1).params.from,undefined);
 page.clearFilters();
 assert.deepEqual({...requests.at(-1).params},{scope:'cache',view:'panel'},'clearing filters restores the resident overview request');
}
console.log('ok - resident overview request, investigation context and chart filters');
