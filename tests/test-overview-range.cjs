const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const ts=require('../frontend/node_modules/typescript');
const compile=path=>ts.transpileModule(fs.readFileSync(path,'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS,experimentalDecorators:true}}).outputText;
const decorator=()=>value=>value;
const angular={Component:decorator,Injectable:decorator,ChangeDetectionStrategy:{Eager:0}};
const core={};
vm.runInNewContext(compile('frontend/src/app/core.ts'),{exports:core,require:name=>name==='@angular/core'?angular:{}});
const viewport={};vm.runInNewContext(compile('frontend/src/app/chart-viewport.ts'),{exports:viewport});
const key='ndr.angular.overview.range';
function fixture(storage=new Map()){
 const requests=[],investigations=[],contexts=[];
 class LiveQuery {start(path,params,topic){requests.push({path,params,topic});}stop(){}}
 const exported={};
 vm.runInNewContext(compile('frontend/src/app/pages/overview.component.ts'),{exports:exported,require:name=>name==='@angular/core'?angular:name==='../chart-viewport'?viewport:name==='../core'?{...core,LiveQuery}:{},localStorage:{getItem:name=>storage.get(name)??null,setItem:(name,value)=>storage.set(name,value)}});
 return {page:new exported.OverviewComponent({}, {investigate:(query,ts,range)=>{investigations.push(query);contexts.push(JSON.parse(JSON.stringify(range)));}}, {}),requests,storage,investigations,contexts};
}
{
 const {page}=fixture();
 assert.match(page.networkStatus({available:false,status:'pending'}),/准备/);
 assert.match(page.networkStatus({available:false,status:'error'}),/暂不可用/);
 assert.match(page.networkStatus({available:true,status:'refreshing'}),/显示上次结果/);
 assert.match(page.networkStatus({available:true,status:'stale'}),/更新延迟/);
 assert.equal(page.networkStatus({available:true,status:'ready'}),'');
}
{
 const {page,investigations}=fixture();
 page.investigateTop({key:'signatures'},{sid:2021076});
 page.investigateTop({key:'signatures'},{sig:'engine drop: flow drop'});
 page.investigateTop({key:'sources',field:'src'},{ip:'2001:db8::1'});
 assert.deepEqual(investigations,['sid: 2021076','type: drop AND sig: "engine drop: flow drop"','src: "2001:db8::1"']);
}
{
 const {page,contexts}=fixture();page.rangeChoice='60';page.investigate('type: alert AND level: high');assert.equal(contexts.at(-1).choice,'60');
 page.rangeChoice='custom';page.customFrom='2026-10-01T09:00';page.customTo='2026-10-02T17:00';page.investigateTop({key:'signatures'},{sid:2021076});
 assert.deepEqual(contexts.at(-1),{choice:'custom',from:page.customFrom,to:page.customTo});
}
{
 const {page,requests,storage}=fixture();page.ngOnInit();
 assert.equal(page.rangeChoice,'1440');assert.equal(requests[0].params.window,'1440');
 page.rangeChoice='10080';page.setRange(core.timeRange(page.rangeChoice,'',''));
 const restored=fixture(storage);restored.page.ngOnInit();
 assert.equal(restored.page.rangeChoice,'10080');assert.equal(restored.requests[0].params.window,'10080');
 assert.deepEqual([...storage.keys()],[key],'only the overview preference is persisted');
 page.rangeChoice='custom';page.customFrom='2026-10-01T09:00';page.customTo='2026-10-02T17:00';
 page.setRange(core.timeRange(page.rangeChoice,page.customFrom,page.customTo));
 const custom=fixture(storage);custom.page.ngOnInit();
 assert.equal(custom.page.customFrom,page.customFrom);assert.equal(custom.page.customTo,page.customTo);
 assert.equal(custom.requests[0].params.from,String(+new Date(page.customFrom)/1000));
 assert.equal(custom.requests[0].params.to,String(+new Date(page.customTo)/1000));
 page.rangeChoice='1440';page.setRange({window:'1440'});
 const reset=fixture(storage);reset.page.ngOnInit();assert.equal(reset.requests[0].params.window,'1440');
 assert.equal(JSON.parse(storage.get(key)).from,undefined,'reset removes the custom interval');
}
for(const saved of ['{broken',JSON.stringify({choice:'all'}),JSON.stringify({choice:'custom',from:'invalid',to:'invalid'}),JSON.stringify({choice:'custom',from:'2026-11-02T00:00',to:'2026-11-01T00:00'})]){
 const {page,requests}=fixture(new Map([[key,saved]]));page.ngOnInit();assert.equal(requests[0].params.window,'1440');
}
{
 const storage={get(){throw new Error('storage blocked');},set(){throw new Error('storage blocked');}};
 const {page,requests}=fixture(storage);page.ngOnInit();assert.equal(requests[0].params.window,'1440');
 page.rangeChoice='60';page.setRange({window:'60'});assert.equal(requests[1].params.window,'60');
}
for(const choice of ['today','yesterday']){
 const {page,requests}=fixture(new Map([[key,JSON.stringify({choice})]]));page.ngOnInit();
 const expected=core.timeRange(choice,'','');assert.equal(requests[0].params.from,expected.from);assert.equal(requests[0].params.to,expected.to);
}
{
 const {page,requests,investigations}=fixture();page.ngOnInit();page.rangeChoice='15';
 page.filterKind('alerts','检测告警');assert.equal(requests.at(-1).params.detection,'alerts');assert.equal(requests.at(-1).params.window,'15');
 page.filterTop({key:'sources',field:'src'},{ip:'2001:db8::1'});assert.equal(requests.at(-1).params.src,'2001:db8::1');
 page.filterKind('high','高危告警');assert.equal(requests.at(-1).params.detection,'high');assert.equal(page.filters.filter(f=>f.key==='kind').length,1);
 page.filterTop({key:'signatures'},{sid:498});assert.equal(requests.at(-1).params.sid,'498');
 page.removeFilter('src');assert.equal(requests.at(-1).params.src,undefined);assert.equal(requests.at(-1).params.sid,'498');
 assert.equal(investigations.length,0,'numeric and chart filters stay in overview');
 page.clearFilters();assert.equal(page.filters.length,0);assert.equal(requests.at(-1).params.detection,undefined);
 page.filterNetwork({title:'应用',field:'app',type:'flow'},{name:'未识别'});assert.equal(requests.at(-1).params.app,'');assert.equal(requests.at(-1).params.type,undefined,'application filters retain the complete connection cohort');
 page.investigateNetwork({field:'app',type:'flow'},{name:'tls'});assert.equal(investigations.at(-1),'type: flow AND app: "tls"','text table keeps investigation navigation');
 page.clearFilters();page.data={bucket:1};const t=Math.floor(Date.now()/1000)-120;
 page.filterTrend({point:{t},kind:'drops'});assert.equal(requests.at(-1).params.from,String(t));assert.equal(requests.at(-1).params.to,String(t+60-.001));
 assert.equal(requests.at(-1).params.detection,'drops');page.removeFilter('period');assert.equal(requests.at(-1).params.from,undefined);
 page.data={bucket:1};page.filterTrend({point:{t},kind:'alerts'});page.rangeChoice='60';page.setRange({window:'60'});
 assert.equal(requests.at(-1).params.from,undefined,'changing range clears the selected time bucket');assert.equal(requests.at(-1).params.detection,'alerts');
}
console.log('ok - overview defaults, persistence, custom ranges, calendar presets, reset and unavailable storage');
