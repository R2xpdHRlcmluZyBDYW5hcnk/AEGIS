import { TabMotionDirective } from './tab-motion.directive';
import { Component, Injectable, signal, effect, untracked, ChangeDetectionStrategy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Api, ConsoleState, action, date, severity, localDate } from './core';
import { TableComponent, Column, lastPageOffset } from './table.component';
import { ModalComponent } from './modal.component';
import { evidenceGroups, eventType } from './event-fields';
import { ConnectionSummaryComponent } from './connection-summary.component';
import { AttackMappingComponent } from './attack-mapping.component';
import { mappingFromEvent, mappingFromMetadata, mappingFromRule } from './attack-mapping';
import { generateLocal } from './local-assistant';
import { AssistantMarkdownPipe } from './assistant-markdown.pipe';
function drawerGroups(record:any){const {flow_id,...visible}=record;return evidenceGroups(visible);}

// Reindent the original tokens so 64-bit native identifiers retain every digit.
export function prettyJson(raw:string):string {
 let depth=0,quoted=false,escaped=false,out='';
 const indent=()=> '  '.repeat(depth);
 for(let i=0;i<raw.length;i++){
  const c=raw[i];
  if(quoted){out+=c;if(escaped)escaped=false;else if(c==='\\')escaped=true;else if(c==='"')quoted=false;continue;}
  if(c==='"'){quoted=true;out+=c;}
  else if(c==='{'||c==='['){out+=c;depth++;if(!/^[\s]*[}\]]/.test(raw.slice(i+1)))out+='\n'+indent();}
  else if(c==='}'||c===']'){depth=Math.max(0,depth-1);if(!/[{\[]\s*$/.test(out))out+='\n'+indent();out+=c;}
  else if(c===',')out+=',\n'+indent();
  else if(c===':')out+=': ';
  else if(!/\s/.test(c))out+=c;
 }
 return out;
}

@Injectable({providedIn:'root'})
export class Details {
 readonly stack=signal<any[]>([]);
 private sequence=0;
 private inference?:AbortController;
 private evidenceRequest?:AbortController;
 get current():any{return this.stack().at(-1);}
 constructor(private api:Api,state:ConsoleState){
  effect(()=>{state.page();untracked(()=>this.dismiss());});
  window.addEventListener('pagehide',()=>this.stopGeneration());
  window.addEventListener('beforeunload',()=>this.stopGeneration());
 }
 stopGeneration():void{
  this.inference?.abort();
  this.inference=undefined;
  this.stack.update(s=>s.map(v=>v.aiBusy?{...v,aiBusy:'',aiError:'已停止生成',aiProcessOpen:false}:v));
 }
 private stopEvidence():void{this.evidenceRequest?.abort();this.evidenceRequest=undefined;this.stack.update(s=>s.map(v=>v.sessionBusy?{...v,sessionBusy:false}:v));}
 close():void{this.stopGeneration();this.stopEvidence();this.stack.update(s=>s.slice(0,-1));if(this.current?.kind==='event')void this.sessionPage(this.current.session?.offset||0);}
 dismiss():void{this.stopGeneration();this.stopEvidence();this.stack.set([]);}
 private patch(id:number,patch:any):void{this.api.zone.run(()=>this.stack.update(s=>s.map(v=>v.id===id?{...v,...patch}:v)));}
 async generate(kind:'summary'|'rule'):Promise<void>{
  const view=this.current;if(!view||view.status!=='ready'||view.aiBusy)return;
  const target=view.kind==='incident'?{kind:'incident',params:view.params}:view.record?.record_id?{kind:'record',key:view.record.record_id}:view.record?.id!=null?{kind:'event',id:view.record.id}:null;
  if(!target){this.patch(view.id,{aiError:'当前证据缺少可查询标识，无法生成'});return;}
  this.stopGeneration();const controller=this.inference=new AbortController();
  this.patch(view.id,{aiBusy:kind,aiError:'',aiDraft:'',aiActivity:'正在读取证据',aiReasoning:false,aiThoughts:[],aiNotes:[],aiNewNote:true,aiProcessOpen:true,aiAnalysisDone:false,...(kind==='rule'?{aiRule:null,aiAdded:null,aiApplyError:''}:{aiSummary:null})});
  const update=(item:any)=>{
   if(controller.signal.aborted||this.current?.id!==view.id)return;
   const active=this.current;
   if(item.progress){
    const {id,label,detail}=item.progress;
    this.patch(view.id,{aiActivity:[label,detail].filter(Boolean).join(' '),aiRepairing:id==='compose-fallback',aiNewNote:true,aiReasoning:false});
   }
   if(typeof item.reasoning_delta==='string'&&item.reasoning_delta){
    const thoughts:string[]=[...active.aiThoughts];
    if(active.aiReasoning&&thoughts.length)thoughts[thoughts.length-1]+=item.reasoning_delta;
    else thoughts.push(item.reasoning_delta);
    this.patch(view.id,{aiThoughts:thoughts,aiReasoning:true});
   }
   if(typeof item.analysis_delta==='string'&&item.analysis_delta){
    const notes:string[]=[...active.aiNotes];
    if(active.aiNewNote||!notes.length)notes.push(item.analysis_delta);
    else notes[notes.length-1]+=item.analysis_delta;
    this.patch(view.id,{aiNotes:notes,aiNewNote:false});
   }
   if(item.analysis_done&&!active.aiAnalysisDone)this.patch(view.id,{aiAnalysisDone:true,aiProcessOpen:false});
   if(typeof item.delta==='string')this.patch(view.id,{aiDraft:(item.replace_draft?'':this.current.aiDraft||'')+item.delta});
  };
  try{const result=await generateLocal(kind,target,controller.signal,view.aiRuleAction||'alert',update);if(!controller.signal.aborted&&this.current?.id===view.id)this.patch(view.id,{[kind==='rule'?'aiRule':'aiSummary']:result,aiDraft:'',aiAnalysisDone:true,aiProcessOpen:this.current.aiAnalysisDone?this.current.aiProcessOpen:false});}
  catch(e:any){if(!controller.signal.aborted&&this.current?.id===view.id)this.patch(view.id,{aiError:e.message});}
  finally{
   if(this.inference===controller){
    this.inference=undefined;
    this.patch(view.id,{aiBusy:''});
   }
  }
 }
 toggleProcess(event:Event):void{
  const view=this.current,open=(event.target as HTMLDetailsElement).open;
  if(!view||view.aiProcessOpen===open)return;
  this.patch(view.id,{aiProcessOpen:open});
 }
 setRuleAction(action:string):void{const view=this.current;if(!view||view.aiBusy||view.aiApplying||view.aiAdded||!['alert','block'].includes(action))return;this.patch(view.id,{aiRuleAction:action,aiRule:null,aiError:''});}
 async addRule():Promise<void>{
  const view=this.current;if(!view?.aiRule?.proposal||view.aiApplying||view.aiAdded)return;
  this.patch(view.id,{aiApplying:true,aiApplyError:''});
  try{
   const result=await this.api.post('/api/ai/rules/add',{proposal:view.aiRule.proposal});
   this.patch(view.id,{aiAdded:result});
   // This is an explicitly accepted rule transaction; closing the drawer only stops inference.
   while(this.current?.id===view.id){
    const status=await this.api.get('/api/actions/status');
    if(status.id!==result.job_id){this.patch(view.id,{aiApplyError:'请到签名管理查看应用结果'});break;}
    if(status.state==='done'){this.patch(view.id,{aiApplyStatus:status,aiApplyError:status.rc===0?'':'签名应用失败，已尝试恢复旧签名；请到签名管理查看任务日志'});break;}
    await new Promise(resolve=>setTimeout(resolve,750));
   }
  }catch(e:any){this.patch(view.id,{aiApplyError:e.message});}
  finally{this.patch(view.id,{aiApplying:false});}
 }
 private async open(kind:string,title:string,key:string,loader:()=>Promise<any>):Promise<void>{
  if(this.current?.key===key&&this.current?.status==='loading')return;
  this.stopGeneration();
  this.stopEvidence();
  if(this.current)this.current.scrollTop=document.querySelector('ndr-details .modal-scroll')?.scrollTop||0;
  const view={id:++this.sequence,key,kind,title,status:'loading',scrollTop:0,tab:'network',loader};
  this.api.zone.run(()=>this.stack.update(s=>[...s,view]));
  await this.load(view);
 }
 private async load(view:any):Promise<void>{
  this.api.zone.run(()=>this.stack.update(s=>s.map(item=>item.id===view.id?{...item,status:'loading',error:''}:item)));
  try{const payload=await view.loader();this.api.zone.run(()=>this.stack.update(s=>s.map(item=>item.id===view.id?{...item,...payload,status:'ready'}:item)));if(this.current?.id===view.id&&view.kind==='event')void this.sessionPage(0);}
  catch(e:any){this.api.zone.run(()=>this.stack.update(s=>s.map(item=>item.id===view.id?{...item,status:'error',error:e.message}:item)));}
 }
 retry():void{if(this.current)void this.load(this.current);}
 incident(row:any,params:any):Promise<void>{return this.open('incident','安全事件研判','incident:'+row.id,async()=>({params:{...params,id:row.id,view:'list'},data:this.incidentData(await this.api.get('/api/incident',{...params,id:row.id,view:'list'}))}));}
 private incidentData(data:any):any{return {...data,attackMapping:mappingFromMetadata(data.attack),network:(data.network||[]).map((r:any)=>({...r,summary:r.sig||r.sni||r.dns||r.host||r.reason||r.type}))};}
 async networkPage(offset:number):Promise<void>{
  const view=this.current;if(!view||view.networkBusy)return;
  const update=(patch:any)=>this.api.zone.run(()=>this.stack.update(s=>s.map(v=>v.id===view.id?{...v,...patch}:v)));
  update({networkBusy:true,networkError:''});
  try{
   while(this.current?.id===view.id){
    const data=await this.api.get('/api/incident',{...view.params,network_offset:offset});
    const last=lastPageOffset(data.incident.network_count,data.network_limit||50);
    if(offset<=last){update({data:this.incidentData(data)});break;}
    offset=last;
   }
  }catch(e:any){update({networkError:e.message});}finally{update({networkBusy:false});}
 }
 async sessionPage(offset:number):Promise<void>{
  const view=this.current;if(view?.kind!=='event'||view.showSession===false||!view.record?.session_id||view.sessionBusy)return;
  this.stopEvidence();const request=this.evidenceRequest=new AbortController();this.patch(view.id,{sessionBusy:true,sessionError:''});
  try{
   while(!request.signal.aborted&&this.current?.id===view.id){
    const result=await this.api.get('/api/session',{session_id:view.record.session_id,offset,limit:50},request.signal);
    const last=lastPageOffset(result.total);
    if(offset>last){offset=last;continue;}
    if(!request.signal.aborted&&this.current?.id===view.id)this.patch(view.id,{session:{...result,events:(result.events||[]).map((r:any)=>({...r,summary:r.sig||r.sni||r.dns||r.host||r.type}))}});
    break;
   }
  }
  catch(e:any){if(!request.signal.aborted)this.patch(view.id,{sessionError:e.message});}
  finally{if(this.evidenceRequest===request){this.evidenceRequest=undefined;this.patch(view.id,{sessionBusy:false});}}
 }
 rule(row:any):Promise<void>{const sid=row.sid||row.sig_id,gid=row.gid||1,selector='sid:'+(gid===1?'':gid+':')+sid;return this.open('rule','签名详情 '+gid+':'+sid,'rule:'+gid+':'+sid,async()=>{
  let rule=row;
  if(!rule.line&&!rule.builtin){const d=await this.api.get('/api/rules/search',{q:selector,limit:1});rule=d.rules?.[0];}
  if(!rule?.line&&!rule?.builtin)throw new Error('当前目录未找到该签名原文');return {data:rule,attackMapping:mappingFromRule(rule.line||'')};
 });}
 event(row:any,showSession=true):Promise<void>{return this.open('event','事件证据','event:'+(row.record_id||row.id||row.ts)+'/'+row.sig_id,async()=>{
  if(row.record_id){const result=await this.api.get('/api/record',{key:row.record_id});return {showSession,data:result.raw,rawText:result.raw_text?prettyJson(result.raw_text):undefined,record:{...result.record,record_id:row.record_id},groups:drawerGroups(result.record),attackMapping:mappingFromEvent(result.record,result.raw)};}
  let raw=row._raw;const rawText=typeof raw==='string'?raw:undefined;if(raw)raw=typeof raw==='string'?JSON.parse(raw):raw;else if(row.id!=null)raw=await this.api.get('/api/event/'+row.id);else raw={...row};
  return {showSession,data:raw,rawText:rawText?prettyJson(rawText):undefined,record:row,groups:drawerGroups(row),attackMapping:mappingFromEvent(row,raw)};
 });}
}
@Component({changeDetection:ChangeDetectionStrategy.Eager,selector:'ndr-details',standalone:true,imports:[TabMotionDirective,CommonModule,TableComponent,ModalComponent,AttackMappingComponent,ConnectionSummaryComponent,AssistantMarkdownPipe],template:`
 <ndr-modal *ngIf="details.current as view" [title]="view.title" [busy]="banning" [drawer]="true" [canBack]="details.stack().length>1" [viewKey]="view.id" [restoreScroll]="view.scrollTop" (back)="details.close()" (closed)="details.dismiss()">
  <div class="detail-loading" role="status" *ngIf="view.status==='loading'"><span class="loading-dot"></span>正在加载{{view.kind==='rule'?'签名详情':'事件详情'}}…</div>
  <div class="detail-error" role="alert" *ngIf="view.status==='error'"><h3>暂时无法加载</h3><p>{{view.error}}</p><button class="quiet" (click)="details.retry()">重新加载</button></div>
  <ng-container *ngIf="view.status==='ready'">
   <section class="evidence-group local-assistant" *ngIf="view.kind==='incident'||view.kind==='event'" aria-label="本地智能研判">
    <div class="section-heading"><h3>本地智能研判</h3><span class="badge">Qwen3.5-2B</span></div>
    <div class="ai-body">
    <div class="toolbar"><button class="quiet" [disabled]="!!view.aiBusy" (click)="details.generate('summary')">{{view.aiBusy==='summary'?'正在总结…':view.aiSummary?'重新生成总结':(view.record?.session_id||view.data?.incident?.session_id)?'生成会话总结':'生成事件总结'}}</button><label class="checkbox-label">签名动作 <select aria-label="签名动作" [value]="view.aiRuleAction||'alert'" [disabled]="!!view.aiBusy||view.aiApplying||!!view.aiAdded" (change)="details.setRuleAction($any($event.target).value)"><option value="alert">告警</option><option value="block">阻断匹配特征</option></select></label><button class="quiet" [disabled]="!!view.aiBusy||view.aiApplying||!!view.aiAdded" (click)="details.generate('rule')">{{view.aiBusy==='rule'?'正在生成签名…':view.aiRule?'重新生成签名建议':'生成签名建议'}}</button><button class="text-button" *ngIf="view.aiBusy" (click)="details.stopGeneration()">停止生成</button></div>
    <div class="ai-output" role="region" aria-label="研判输出" tabindex="0" *ngIf="view.aiBusy||view.aiError||view.aiThoughts?.length||view.aiNotes?.length||view.aiDraft||view.aiSummary||view.aiRule">
    <p class="muted ai-activity" *ngIf="view.aiBusy&&(view.aiRepairing||!view.aiAnalysisDone&&view.aiNewNote&&!view.aiReasoning)" role="status">{{view.aiActivity}}</p>
    <p class="error" *ngIf="view.aiError" role="alert">{{view.aiError}}</p>
    <details class="ai-hunts ai-process" *ngIf="view.aiThoughts?.length||view.aiNotes?.length" [open]="view.aiProcessOpen" (toggle)="details.toggleProcess($event)">
     <summary>{{view.aiThoughts?.length?'思考过程':'分析说明'}}</summary>
     @for (thought of view.aiThoughts; track $index) {<div class="muted ai-thought ai-markdown" [innerHTML]="thought | assistantMarkdown"></div>}
     <h4 *ngIf="view.aiThoughts?.length&&view.aiNotes?.length">分析说明</h4>
     @for (note of view.aiNotes; track $index) {<div class="muted ai-note ai-markdown" [innerHTML]="note | assistantMarkdown"></div>}
    </details>
    <div class="ai-summary ai-draft" *ngIf="view.aiDraft&&!view.aiSummary"><div class="section-heading"><h4>{{view.aiBusy?'正在生成总结':'未完成的总结'}}</h4></div><div class="ai-markdown" [innerHTML]="view.aiDraft | assistantMarkdown"></div></div>
    <div *ngIf="view.aiSummary as summary" class="ai-summary"><div class="section-heading"><h4>{{summary.context?.scope==='session'?'会话总结':'事件总结'}}</h4><button class="text-button" (click)="copy(summary.text)">复制总结</button></div><div class="ai-markdown" [innerHTML]="summary.text | assistantMarkdown"></div><p class="muted" *ngIf="summary.context as context">已检索 {{context.total_records}} 条{{context.scope==='session'?'会话':'事件'}}记录 使用 {{context.evidence_records}} 条证据摘录<span *ngIf="context.related_evidence_records"> 附加 {{context.related_evidence_records}} 条关联日志摘录</span></p><small class="muted">依据已保留的日志分析，请结合原始证据核查</small>
     <details class="ai-hunts" *ngIf="summary.hunts?.length"><summary>关联检索</summary><section *ngFor="let hunt of summary.hunts"><div class="section-heading"><span>{{hunt.label}}</span><span class="badge">{{hunt.error_kind==='validation'?'条件无效':hunt.error?'检索失败':'命中 '+hunt.total+' 条'}}</span><button class="text-button" *ngIf="hunt.query&&!hunt.error" (click)="openSummaryHunt(hunt.query,summary.context,hunt.range)">查看命中日志 ↗</button></div><span class="badge" *ngIf="hunt.scope==='related'">关联候选线索</span><pre>{{hunt.query||hunt.predicate}}</pre><p class="muted" *ngIf="hunt.error">{{hunt.error}}</p></section></details>
     <details class="ai-hunts" *ngIf="summary.dns_clues?.records?.length"><summary>DNS 候选关联</summary><p class="muted">同客户端曾解析到目标 IP，属于可能相关的独立 DNS 证据，不能据此确认连接使用了该域名。</p><section *ngFor="let clue of summary.dns_clues.records"><strong>{{clue.name}}</strong><p>{{clue.answer}} {{dt(clue.ts)}}</p><p class="muted">最小应答 TTL {{clue.ttl_seconds??'未知'}}<span *ngIf="clue.ttl_seconds!=null"> 秒</span> {{clue.name_matches?'与当前域名线索一致':'域名线索尚待核查'}}</p><p class="muted">会话 ID <code>{{clue.session_id||'未采集'}}</code></p><div class="toolbar"><button class="text-button" *ngIf="clue.session_id" (click)="openDnsSession(clue.session_id)">查看 DNS 会话 ↗</button><button class="text-button" *ngIf="clue.record_id" (click)="details.event(clue,false)">查看 DNS 日志 ↗</button></div></section></details>
     <p class="muted" *ngIf="summary.truncated" role="status">模型达到生成上限，以上为已输出的部分总结</p>
     <p class="muted" *ngIf="summary.hunt_status==='invalid'">模型未提供可执行的关联条件，本次总结依据当前证据</p><p class="muted" *ngIf="summary.hunt_status==='partial'">部分关联检索未完成</p><p class="muted" *ngIf="summary.hunt_status==='not_needed'">模型未提出需要扩展检索的线索</p>
    </div>
    <div *ngIf="view.aiRule as rule" class="ai-rule"><h4>Snort 3 签名建议</h4><p *ngIf="rule.unavailable">{{rule.reason}}</p><ng-container *ngIf="rule.rule"><p>{{rule.scope}}</p><pre>{{rule.rule}}</pre><p>{{rule.reason}}</p><p>{{rule.limitations}}</p><p class="muted">{{rule.notice}}</p><div class="toolbar"><strong class="rule-source">手动签名</strong><button [disabled]="view.aiApplying||!!view.aiAdded" (click)="details.addRule()">{{view.aiApplying?'正在校验并应用…':view.aiAdded?'已提交应用':'添加并应用签名'}}</button></div><p class="muted">SID 在添加时分配，仅保存到独立手动签名文件</p><p role="status" *ngIf="view.aiApplyStatus?.rc===0">手动签名 {{view.aiAdded.sid}} 已通过校验并应用</p><p class="error" role="alert" *ngIf="view.aiApplyError">{{view.aiApplyError}}</p></ng-container></div>
    </div>
    </div>
   </section>
   <ng-container *ngIf="view.kind==='incident'">
    <div class="detail-actions"><div class="toolbar"><button (click)="investigate(view.data.incident)" [disabled]="investigating || !canInvestigate(view.data.incident)">{{investigating?'正在准备调查…':'调查关联事件 ↗'}}</button></div><div class="toolbar"><button class="quiet danger" [disabled]="!view.data.incident.src || banning" (click)="ban(view.data.incident.src)">封禁源地址</button><button class="quiet danger" [disabled]="!view.data.incident.dst || banning" (click)="ban(view.data.incident.dst)">封禁目的地址</button></div></div>
    <div class="incident-heading"><div class="detail-tags"><span class="badge" [class.danger]="view.data.incident.sev===1">{{sev(view.data.incident.sev)}}</span><span class="badge" [class.danger]="view.data.incident.action==='blocked'">{{act(view.data.incident.action)}}</span></div><h3>{{view.data.incident.sig}}</h3><p class="muted">{{dt(view.data.incident.first_ts)}} — {{dt(view.data.incident.last_ts)}}</p></div>
    <p class="muted" *ngIf="view.data.incident.session_id">会话 ID：{{view.data.incident.session_id}}</p><p class="muted" *ngIf="view.data.incident.tuple_hash">五元组关联键：{{view.data.incident.tuple_hash}}</p><div class="mini-stats"><div><small>告警</small><strong>{{view.data.incident.alert_count}}</strong></div><div><small>检测签名</small><strong>{{view.data.incident.signature_count}}</strong></div><div><small>关联网络日志</small><strong>{{view.data.incident.network_count}}</strong></div></div>
    <div class="path"><div><small>源地址</small><span>{{endpoint(view.data.incident.src,view.data.incident.sport)}}</span></div><b aria-hidden="true">→</b><div><small>目的地址</small><span>{{endpoint(view.data.incident.dst,view.data.incident.dport)}}</span></div></div>
    <ndr-attack-mapping [mapping]="view.data.attackMapping"/>
    <div ndrTabMotion class="tabs detail-tabs" role="tablist" aria-label="事件研判内容"><button role="tab" id="detail-tab-network" aria-controls="detail-panel-network" [attr.tabindex]="view.tab==='network'?0:-1" (keydown)="tabKey($event,view,'network')" [attr.aria-selected]="view.tab==='network'" [class.active]="view.tab==='network'" (click)="view.tab='network'">网络时间线</button><button role="tab" id="detail-tab-alerts" aria-controls="detail-panel-alerts" [attr.tabindex]="view.tab==='alerts'?0:-1" (keydown)="tabKey($event,view,'alerts')" [attr.aria-selected]="view.tab==='alerts'" [class.active]="view.tab==='alerts'" (click)="view.tab='alerts'">告警证据</button><button role="tab" id="detail-tab-signatures" aria-controls="detail-panel-signatures" [attr.tabindex]="view.tab==='signatures'?0:-1" (keydown)="tabKey($event,view,'signatures')" [attr.aria-selected]="view.tab==='signatures'" [class.active]="view.tab==='signatures'" (click)="view.tab='signatures'">检测签名</button></div>
    <section animate.enter="section-enter" class="detail-section" role="tabpanel" id="detail-panel-signatures" aria-labelledby="detail-tab-signatures" *ngIf="view.tab==='signatures'"><h3>检测签名</h3><ndr-table id="incident-signatures" [columns]="signatureColumns" [rows]="view.data.incident.signatures" keyField="sid" [interactive]="true" (rowOpen)="details.rule($event)"/></section>
    <section animate.enter="section-enter" class="detail-section" role="tabpanel" id="detail-panel-alerts" aria-labelledby="detail-tab-alerts" *ngIf="view.tab==='alerts'"><h3>原始告警证据</h3><ndr-table id="incident-alerts" [columns]="eventColumns" [rows]="view.data.alerts" [interactive]="true" (rowOpen)="details.event($event)"/></section>
    <section animate.enter="section-enter" class="detail-section" role="tabpanel" id="detail-panel-network" aria-labelledby="detail-tab-network" *ngIf="view.tab==='network'"><h3>关联网络时间线</h3><p class="error" role="alert" *ngIf="view.networkError">{{view.networkError}}</p><ndr-table id="incident-network" [total]="view.data.incident.network_count" [offset]="view.data.network_offset || 0" [size]="view.data.network_limit || 50" [busy]="view.networkBusy" (pageChange)="details.networkPage($event)" [columns]="networkColumns" [rows]="view.data.network" [interactive]="true" (rowOpen)="details.event($event)"/></section>
   </ng-container>
   <ng-container *ngIf="view.kind==='rule'"><div class="detail-actions"><button (click)="investigateRule(view.data.sid,view.data.gid)">调查相关事件 ↗</button></div><section class="evidence-group"><h3>签名信息</h3><dl class="evidence-fields"><div class="wide"><dt>签名描述</dt><dd>{{view.data.msg || '手动签名'}}</dd></div><div><dt>签名编号（GID:SID）</dt><dd>{{view.data.gid||1}}:{{view.data.sid}}</dd></div><div><dt>实际动作</dt><dd>{{view.data.action || '—'}}</dd></div><div *ngIf="view.data.classtype"><dt>威胁分类</dt><dd>{{view.data.classtype}}</dd></div><div class="wide" *ngIf="view.data.origins?.length"><dt>签名来源</dt><dd><span *ngFor="let o of view.data.origins"><strong class="rule-source">{{o.source}}</strong> {{o.group}} </span></dd></div></dl></section><ndr-attack-mapping [mapping]="view.attackMapping" source="当前签名元数据"/><p class="muted" *ngIf="view.data.builtin"><strong class="rule-source">Snort 内置</strong> 检测签名，支持按签名或分组抑制告警。</p><section class="evidence-group" *ngIf="view.data.line"><div class="section-heading"><h3>签名原文</h3><button class="text-button" (click)="copy(view.data.line)">复制原文</button></div><pre>{{view.data.line}}</pre></section></ng-container>
   <ng-container *ngIf="view.kind==='event'"><div class="detail-actions"><div class="toolbar"><button [disabled]="investigating || !canInvestigate(view.record)" (click)="investigate(view.record)">{{investigating?'正在准备调查…':'调查关联事件 ↗'}}</button><button class="quiet" *ngIf="view.record.sig_id" (click)="details.rule(view.record)">检测签名</button></div><button class="quiet danger" [disabled]="!view.record.src || banning" (click)="ban(view.record.src)">封禁源地址</button></div>
    <div class="evidence-heading"><div class="detail-tags"><span class="badge">{{eventName(view.record.type)}}</span><span class="badge" *ngIf="view.record.action" [class.danger]="view.record.action==='blocked'">{{act(view.record.action)}}</span></div><h3><ndr-connection-summary *ngIf="['flow','session'].includes(view.record.type);else eventHeading" [record]="view.record" [wrap]="true"/><ng-template #eventHeading>{{view.record.sig || view.record.host || view.record.sni || view.record.dns || eventName(view.record.type)}}</ng-template></h3><p class="muted">{{dt(view.record.ts)}}</p></div>
    <section class="evidence-group session-evidence" *ngIf="view.showSession!==false&&view.record.session_id"><header class="section-heading"><h3>会话</h3><button class="quiet" [disabled]="view.sessionBusy" (click)="details.sessionPage(view.session?.offset || 0)">刷新</button></header><p class="error" role="alert" *ngIf="view.sessionError">{{view.sessionError}}</p><ndr-table id="session-evidence" [columns]="networkColumns" [rows]="view.session?.events || []" [total]="view.session?.total || 0" [offset]="view.session?.offset || 0" [busy]="view.sessionBusy" [interactive]="true" (pageChange)="details.sessionPage($event)" (rowOpen)="details.event($event,false)"/></section>
    <ndr-attack-mapping [mapping]="view.attackMapping"/>
    <section class="evidence-group" *ngFor="let group of view.groups"><h3>{{group.title}}</h3><dl class="evidence-fields"><div *ngFor="let field of group.fields" [class.wide]="['sig','url','ua','answers','community'].includes(field.key)"><dt>{{field.label}}</dt><dd><ndr-connection-summary *ngIf="field.key==='sig'&&['flow','session'].includes(view.record.type);else evidenceFieldValue" [record]="view.record" [wrap]="true"/><ng-template #evidenceFieldValue><span [class.badge]="field.key==='state'&&['flow','session'].includes(view.record.type)" [class.flow-state]="field.key==='state'&&['flow','session'].includes(view.record.type)">{{field.value}}</span></ng-template></dd></div></dl></section>
    <details class="raw-evidence"><summary>原始 JSON</summary><div class="raw-actions"><button class="text-button" (click)="copyJson(view.data,view.rawText)">复制 JSON</button></div><pre>{{view.rawText || (view.data | json)}}</pre></details>
   </ng-container>
  </ng-container>
 </ndr-modal>
`})
export class DetailsComponent {
 dt=date;sev=severity;act=action;eventName=eventType;banning=false;investigating=false;
 signatureColumns:Column[]=[{key:'sid',label:'SID',width:110},{key:'sig',label:'检测签名',width:320},{key:'sev',label:'级别',kind:'severity',width:90},{key:'count',label:'告警数',width:90}];
 eventColumns:Column[]=[{key:'ts',label:'时间',kind:'time',width:180},{key:'sig_id',label:'SID',width:100},{key:'sig',label:'检测签名',width:300},{key:'action',label:'动作',kind:'action',width:100}];
 networkColumns:Column[]=[{key:'ts',label:'时间',kind:'time',width:180},{key:'type',label:'类型',kind:'eventType',width:110},{key:'app',label:'应用',width:100},{key:'summary',label:'网络事件摘要',kind:'eventSummary',width:300},{key:'src',label:'源地址',width:150},{key:'dst',label:'目的地址',width:150},{key:'sni',label:'TLS 服务器名称',width:180},{key:'dns',label:'查询域名',width:180}];
 constructor(public details:Details,public state:ConsoleState,private api:Api){}
 tabKey(event:KeyboardEvent,view:any,tab:string):void{const tabs=['network','alerts','signatures'];let index=tabs.indexOf(tab);if(event.key==='ArrowRight')index=(index+1)%3;else if(event.key==='ArrowLeft')index=(index+2)%3;else if(event.key==='Home')index=0;else if(event.key==='End')index=2;else return;event.preventDefault();view.tab=tabs[index];(event.currentTarget as HTMLElement).parentElement?.querySelectorAll<HTMLButtonElement>('button')[index].focus();}
 endpoint(ip:any,port:any):string{const host=String(ip||'—');return (host.includes(':')?'['+host+']':host)+(port!=null&&port!==''?':'+port:'');}
 canInvestigate(row:any):boolean{return !!(row?.session_id||(row?.id?.startsWith('session:')));}
 async investigate(row:any):Promise<void>{
  if(this.investigating||!this.canInvestigate(row))return;
  const view=this.details.current,community=row.community_id||row.community;
  this.investigating=true;
  try{
   const params:any=row.session_id?{incident_id:'session:'+row.session_id}:community?{community}:{src:row.src,sport:row.sport,dst:row.dst,dport:row.dport,proto:row.proto,...(row.association_flow_id?{flow:row.association_flow_id}:{})};
   if(view?.kind==='incident')Object.assign(params,{incident_id:row.id});
   const result=await this.api.get('/api/hunt/related',params);
   if(this.details.current?.id!==view?.id)return;
   const range=row.session_id||row.id?.startsWith('session:')?{choice:'all',from:'',to:''}:{choice:'custom',from:localDate(new Date(Number(result.from)*1000)),to:localDate(new Date(Number(result.to)*1000))};
   this.state.investigate(result.query,undefined,range);this.details.dismiss();
  }catch(error:any){if(this.details.current?.id===view?.id)this.state.toast(error.message);}
  finally{this.investigating=false;}
 }
 investigateRule(sid:any,gid:any=1):void{this.state.investigate('gid: '+gid+' AND sid: '+sid);this.details.dismiss();}
 openSummaryHunt(query:string,context:any,range?:number[]):void{const from=range?.[0]??context?.from,to=range?.[1]??context?.to;if(!query||from==null||to==null)return;this.state.investigate(query,undefined,{choice:'custom',from:localDate(new Date(Math.floor(from/60)*60000)),to:localDate(new Date(Math.ceil(to/60)*60000))});this.details.dismiss();}
 openDnsSession(session:string):void{if(!/^[0-9a-f]{32}:[0-9a-f]{16}$/.test(session))return;this.state.investigate('session_id:'+JSON.stringify(session),undefined,{choice:'all',from:'',to:''});this.details.dismiss();}
 async copy(value:string):Promise<void>{try{await navigator.clipboard.writeText(value);this.state.toast('已复制');}catch{this.state.toast('当前浏览器无法复制，请选中文本复制');}}
 copyJson(data:any,raw?:string):void{void this.copy(raw || JSON.stringify(data,null,2));}
 async ban(target:string):Promise<void>{if(!target||this.banning)return;if(!await this.state.confirm('封禁地址',target+' 将被加入封禁规则，确定继续？'))return;this.banning=true;try{const d=await this.api.post('/api/bans',{target});this.state.toast(d.message||'已提交封禁');}catch(e:any){this.state.toast(e.message);}finally{this.banning=false;}}
}
