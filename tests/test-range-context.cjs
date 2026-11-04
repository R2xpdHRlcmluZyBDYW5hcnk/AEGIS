const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const ts=require('../frontend/node_modules/typescript');
const compile=path=>ts.transpileModule(fs.readFileSync(path,'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS,experimentalDecorators:true}}).outputText;
let template;
class EventEmitter {values=[];emit(value){this.values.push(value);}}
const noop=()=>()=>{};
const angular={Component:config=>{template=config.template;return value=>value;},Injectable:noop,Input:noop,Output:noop,effect:()=>{},EventEmitter,ChangeDetectionStrategy:{Eager:0}};
const core={};vm.runInNewContext(compile('frontend/src/app/core.ts'),{exports:core,require:name=>name==='@angular/core'?angular:{}});
const component={};vm.runInNewContext(compile('frontend/src/app/range.component.ts'),{exports:component,require:name=>name==='@angular/core'?angular:name==='./core'?core:{}});
assert.ok(!template.includes('全部历史'));assert.ok(!template.includes('关联流范围'));assert.ok(template.includes('*ngIf="sessionScope" value="all"'));assert.equal(new component.RangeComponent().sessionScope,false);
const range=new component.RangeComponent();range.choice='custom';range.reset();assert.equal(range.choice,'1440');assert.equal(range.changed.values.at(-1).window,'1440');
function fixture(bounds,selected=null){
 const requests=[];
 const api={zone:{run:fn=>fn()},get:(path,params)=>path==='/api/hunt/flow-range'?bounds:Promise.resolve({fields:[]})};
 class LiveQuery {start(path,params){requests.push({path,params});}stop(){}}
 const signal=value=>{const f=()=>value;f.set=next=>value=next;return f;};
 const state={views:new Map(),investigation:()=>1,huntFlow:signal(selected?null:'123'),huntRange:signal(selected),huntQuery:signal(selected?'type: alert AND level: high':'flow: 123'),huntTime:signal(null),viewReady(){},toast(){}};
 const exported={};
 vm.runInNewContext(compile('frontend/src/app/pages/events.component.ts'),{exports:exported,require:name=>name==='@angular/core'?angular:name==='../core'?{...core,LiveQuery}:name==='../hunt-fields'?{completeHuntFields:f=>f}:{}});
 const page=new exported.EventsComponent(api,state,{});page.mode='hunt';page.ngOnInit();
 return {page,requests};
}
async function tick(){for(let i=0;i<5;i++)await Promise.resolve();}
(async()=>{
 const preset=fixture(null,{choice:'60',from:'',to:''});assert.equal(preset.page.initialChoice,'60');assert.equal(preset.requests[0].params.window,'60');
 const from=core.localDate(new Date(1793491200000)),to=core.localDate(new Date(1793491260000));
 const custom=fixture(null,{choice:'custom',from,to});assert.equal(custom.page.customFrom,from);assert.equal(custom.page.customTo,to);assert.equal(custom.requests[0].params.from,'1793491200');assert.equal(custom.requests[0].params.to,'1793491260');
 let resolve;
 const normal=fixture(new Promise(done=>resolve=done));
 assert.equal(normal.requests.length,0,'wait for actual flow bounds before querying');
 resolve({from:1793491200,to:1793491260});await tick();
 assert.equal(normal.page.initialChoice,'custom');assert.equal(normal.requests.length,1);
 assert.equal(normal.requests[0].params.from,'1793491200');assert.equal(normal.requests[0].params.to,'1793491260');assert.equal(normal.requests[0].params.q,'flow: 123');
 assert.equal(normal.requests[0].params.all,undefined);
 let finish;
 const changed=fixture(new Promise(done=>finish=done));changed.page.setRange({window:'60'});finish({from:1793491200,to:1793491260});await tick();
 assert.equal(changed.requests.length,1);assert.equal(changed.requests[0].params.window,'60','manual selection overrides delayed flow bounds');
 let later;
 const closed=fixture(new Promise(done=>later=done));closed.page.ngOnDestroy();later({from:1793491200,to:1793491260});await tick();assert.equal(closed.requests.length,0,'leaving the page cancels pending bounds');
 console.log('ok - no history option, actual linked-flow custom range, minute precision and stale-response cancellation');
})().catch(error=>{console.error(error);process.exitCode=1;});
