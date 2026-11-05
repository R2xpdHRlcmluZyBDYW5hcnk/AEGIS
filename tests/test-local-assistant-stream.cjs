const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const ts=require('../frontend/node_modules/typescript');
const source=ts.transpileModule(fs.readFileSync('frontend/src/app/local-assistant.ts','utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS}}).outputText;
const frames=[{progress:{id:'plan',label:'分析线索',state:'running'}},{analysis_done:true},{delta:'通信概览：'},{delta:'测试正文。'},{result:{text:'通信概览：测试正文。'}}];
let cancelled=false;
const bytes=new TextEncoder().encode(frames.map(frame=>JSON.stringify(frame)+'\n').join(''));
const exported={};
vm.runInNewContext(source,{exports:exported,TextDecoder,DOMException,location:{assign(){throw Error('Unexpected login redirect');}},fetch:async()=>new Response(new ReadableStream({start(controller){for(let index=0;index<bytes.length;index+=7)controller.enqueue(bytes.slice(index,index+7));},cancel(){cancelled=true;}}),{headers:{'Content-Type':'application/x-ndjson'}})});
(async()=>{
 const received=[],controller=new AbortController();
 const result=await exported.generateLocal('summary',{kind:'record',key:'fixture'},controller.signal,'alert',frame=>received.push(frame));
 assert.equal(received.map(frame=>frame.delta||'').join(''),'通信概览：测试正文。');
 assert.equal(received[0].progress.label,'分析线索');assert.equal(received[1].analysis_done,true);
 assert.equal(result.text,'通信概览：测试正文。');assert.ok(cancelled,'result cancels the remaining reader');
 const stopped=new AbortController();stopped.abort();
 await assert.rejects(exported.generateLocal('summary',{},stopped.signal),error=>error.name==='AbortError');
 console.log('ok - incremental UTF-8 text and progress frames, final result and abort cancellation');
})().catch(error=>{console.error(error);process.exitCode=1;});
