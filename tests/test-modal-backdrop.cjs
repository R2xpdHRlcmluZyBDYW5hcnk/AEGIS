const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const ts=require('../frontend/node_modules/typescript');
const decorator=()=>()=>{};
class EventEmitter {count=0;emit(){this.count++;}}
const angular={Component:decorator,Input:decorator,Output:decorator,ViewChild:decorator,EventEmitter,ChangeDetectionStrategy:{Eager:0}};
const exportsObject={};
const source=ts.transpileModule(fs.readFileSync('frontend/src/app/modal.component.ts','utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS,experimentalDecorators:true}}).outputText;
vm.runInNewContext(source,{exports:exportsObject,require:name=>name==='@angular/core'?angular:{}});
function fixture(drawer=false){
 const modal=new exportsObject.ModalComponent({});modal.drawer=drawer;
 const element={getBoundingClientRect:()=>({left:100,top:100,right:900,bottom:700})};
 modal.dialog={nativeElement:element};
 const event=(x,y,extra={})=>({target:element,clientX:x,clientY:y,pointerId:1,button:0,...extra});
 return {modal,event};
}
for(const drawer of [false,true]){
 const {modal,event}=fixture(drawer);
 modal.backdropDown(event(20,200));modal.backdropUp(event(20,200));assert.equal(modal.closed.count,1,'both modal types close on backdrop clicks');
 modal.backdropDown(event(200,200));modal.backdropUp(event(200,200));assert.equal(modal.closed.count,1,'interior whitespace is content');
 modal.backdropDown(event(20,200));modal.backdropUp(event(40,200));assert.equal(modal.closed.count,1,'dragging the backdrop does not dismiss');
 modal.backdropDown(event(200,200));modal.backdropUp(event(20,200));assert.equal(modal.closed.count,1,'a selection drag out of content does not dismiss');
 modal.backdropDown(event(20,200));modal.backdropUp(event(20,200,{pointerId:2}));assert.equal(modal.closed.count,1,'unrelated pointers cannot dismiss');
 modal.backdropDown(event(20,200,{button:2}));modal.backdropUp(event(20,200,{button:2}));assert.equal(modal.closed.count,1,'secondary clicks do not dismiss');
 modal.busy=true;modal.backdropDown(event(20,200));modal.backdropUp(event(20,200));assert.equal(modal.closed.count,1,'active writes keep the dialog open');
 modal.busy=false;modal.backdropDown(event(20,200));modal.busy=true;modal.backdropUp(event(20,200));assert.equal(modal.closed.count,1,'writes that start during the gesture also prevent dismissal');
}
console.log('ok - modal and drawer backdrop dismissal preserves content clicks, selections and busy writes');
