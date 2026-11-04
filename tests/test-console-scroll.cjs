const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const ts=require('../frontend/node_modules/typescript');
const source=ts.transpileModule(fs.readFileSync('frontend/src/app/core.ts','utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS,experimentalDecorators:true}}).outputText;
function fixture(){
 let render;
 const main={scrollTop:1700,scrollHeight:3000,clientHeight:1000};
 const signal=value=>{const f=()=>value;f.set=next=>value=next;f.update=fn=>value=fn(value);return f;};
 const angular={Injectable:()=>x=>x,NgZone:class{},signal,afterEveryRender:fn=>render=fn};
 const exports={};
 vm.runInNewContext(source,{exports,require:name=>name==='@angular/core'?angular:{},document:{querySelector:()=>main},window:{scrollY:0,scrollTo(){}},getComputedStyle:()=>({overflowY:'auto'}),location:{hash:'#overview'},history:{pushState(){}},setTimeout,clearTimeout});
 const state=new exports.ConsoleState();
 function leave(){state.navigate('hunt');render();state.viewReady('hunt');render();}
 return {main,state,render:()=>render(),leave};
}
// A saved position can become unreachable when a collapsed panel or fewer rows shorten the page.
{
 const {main,state,render,leave}=fixture();leave();main.scrollHeight=1600;
 state.navigate('overview');render();state.viewReady('overview');render();
 assert.equal(main.scrollTop,600);
 main.scrollTop=0;
 for(let tick=0;tick<4;tick++){state.viewReady('overview');render();assert.equal(main.scrollTop,0,'live updates must not restore an old position');}
}
// Wait for initial content; a later update must not restart completed restoration.
{
 const {main,state,render,leave}=fixture();leave();main.scrollHeight=1000;
 state.navigate('overview');render();assert.equal(main.scrollTop,0);
 main.scrollHeight=3000;render();assert.equal(main.scrollTop,0);
 state.viewReady('overview');render();assert.equal(main.scrollTop,1700);
 main.scrollTop=400;state.viewReady('overview');render();assert.equal(main.scrollTop,400);
}
// Input before a slow response takes precedence over the saved position.
{
 const {main,state,render,leave}=fixture();leave();state.navigate('overview');render();
 state.cancelScrollRestore();main.scrollTop=120;state.viewReady('overview');render();assert.equal(main.scrollTop,120);
}
// An old page's response cannot complete the new page's pending restoration.
{
 const {main,state,render,leave}=fixture();leave();state.navigate('overview');render();
 state.viewReady('hunt');render();assert.equal(main.scrollTop,0);
 state.viewReady('overview');render();assert.equal(main.scrollTop,1700);
}
{
 const {main,state,render,leave}=fixture();leave();state.navigate('overview');render();
 state.scrollKey({key:'PageUp'});main.scrollTop=50;state.viewReady('overview');render();assert.equal(main.scrollTop,50);
}
console.log('ok - scroll restoration runs once after content readiness, clamps shorter pages and yields to user input');
for(const query of ['flow:643267455061940','flow: 643267455061940']){
 const {state}=fixture();state.investigate(query,1793491200);
 assert.equal(state.huntFlow(),'643267455061940','both flow formats retain the linked flow identity');
 assert.equal(state.huntTime(),null);
 assert.equal(state.huntQuery(),query);
}
{
 const {state}=fixture();state.investigate('sid: 2021076');
 assert.equal(state.huntFlow(),null);assert.equal(state.huntQuery(),'sid: 2021076');
}
{
 const {state}=fixture();const range={choice:'60',from:'',to:''};state.investigate('type: alert AND level: high',undefined,range);
 assert.equal(state.huntRange().choice,'60');range.choice='1440';assert.equal(state.huntRange().choice,'60','the shortcut keeps its own time selection');
 state.investigate('sid: 2021076');assert.equal(state.huntRange(),null,'later investigations clear the previous overview range');
}
