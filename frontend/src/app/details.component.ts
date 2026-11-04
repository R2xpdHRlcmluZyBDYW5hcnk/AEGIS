import { TabMotionDirective } from './tab-motion.directive';
import { Component, Injectable, signal, ChangeDetectionStrategy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Api, ConsoleState, action, date, severity, localDate } from './core';
import { TableComponent, Column } from './table.component';
import { ModalComponent } from './modal.component';
import { evidenceGroups, eventType } from './event-fields';
import { ConnectionSummaryComponent } from './connection-summary.component';
import { AttackMappingComponent } from './attack-mapping.component';
import { mappingFromEvent, mappingFromMetadata, mappingFromRule } from './attack-mapping';
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
 get current():any{return this.stack().at(-1);}
 constructor(private api:Api){}
 close():void{this.stack.update(s=>s.slice(0,-1));}
 dismiss():void{this.stack.set([]);}
 private async open(kind:string,title:string,key:string,loader:()=>Promise<any>):Promise<void>{
  if(this.current?.key===key&&this.current?.status==='loading')return;
  if(this.current)this.current.scrollTop=document.querySelector('ndr-details .modal-scroll')?.scrollTop||0;
  const view={id:++this.sequence,key,kind,title,status:'loading',scrollTop:0,tab:'network',loader};
  this.api.zone.run(()=>this.stack.update(s=>[...s,view]));
  await this.load(view);
 }
 private async load(view:any):Promise<void>{
  this.api.zone.run(()=>this.stack.update(s=>s.map(item=>item.id===view.id?{...item,status:'loading',error:''}:item)));
  try{const payload=await view.loader();this.api.zone.run(()=>this.stack.update(s=>s.map(item=>item.id===view.id?{...item,...payload,status:'ready'}:item)));}
  catch(e:any){this.api.zone.run(()=>this.stack.update(s=>s.map(item=>item.id===view.id?{...item,status:'error',error:e.message}:item)));}
 }
 retry():void{if(this.current)void this.load(this.current);}
 incident(row:any,params:any):Promise<void>{return this.open('incident','安全事件研判','incident:'+row.id,async()=>({params:{...params,id:row.id,view:'list'},data:this.incidentData(await this.api.get('/api/incident',{...params,id:row.id,view:'list'}))}));}
 private incidentData(data:any):any{return {...data,attackMapping:mappingFromMetadata(data.attack),network:(data.network||[]).map((r:any)=>({...r,summary:r.sig||r.sni||r.dns||r.host||r.reason||r.type}))};}
 async networkPage(offset:number):Promise<void>{
  const view=this.current;if(!view||view.networkBusy)return;
  const update=(patch:any)=>this.api.zone.run(()=>this.stack.update(s=>s.map(v=>v.id===view.id?{...v,...patch}:v)));
  update({networkBusy:true,networkError:''});
  try{const data=await this.api.get('/api/incident',{...view.params,network_offset:offset});update({data:this.incidentData(data)});}catch(e:any){update({networkError:e.message});}finally{update({networkBusy:false});}
 }
 rule(row:any):Promise<void>{const sid=row.sid||row.sig_id,gid=row.gid||1,selector='sid:'+(gid===1?'':gid+':')+sid;return this.open('rule','规则详情 '+gid+':'+sid,'rule:'+gid+':'+sid,async()=>{
  let rule=row;
  if(!rule.line&&!rule.builtin){const d=await this.api.get('/api/rules/search',{q:selector,limit:1});rule=d.rules?.[0];}
  if(!rule?.line&&!rule?.builtin)throw new Error('当前目录未找到该规则原文');return {data:rule,attackMapping:mappingFromRule(rule.line||'')};
 });}
 event(row:any):Promise<void>{return this.open('event','事件证据','event:'+(row.record_id||row.id||row.ts)+'/'+row.sig_id,async()=>{
  if(row.record_id){const result=await this.api.get('/api/record',{key:row.record_id});return {data:result.raw,rawText:result.raw_text?prettyJson(result.raw_text):undefined,record:result.record,groups:drawerGroups(result.record),attackMapping:mappingFromEvent(result.record,result.raw)};}
  let raw=row._raw;const rawText=typeof raw==='string'?raw:undefined;if(raw)raw=typeof raw==='string'?JSON.parse(raw):raw;else if(row.id!=null)raw=await this.api.get('/api/event/'+row.id);else raw={...row};
  return {data:raw,rawText:rawText?prettyJson(rawText):undefined,record:row,groups:drawerGroups(row),attackMapping:mappingFromEvent(row,raw)};
 });}
}
@Component({changeDetection:ChangeDetectionStrategy.Eager,selector:'ndr-details',standalone:true,imports:[TabMotionDirective,CommonModule,TableComponent,ModalComponent,AttackMappingComponent,ConnectionSummaryComponent],template:`
 <ndr-modal *ngIf="details.current as view" [title]="view.title" [busy]="banning" [drawer]="true" [canBack]="details.stack().length>1" [viewKey]="view.id" [restoreScroll]="view.scrollTop" (back)="details.close()" (closed)="details.dismiss()">
  <div class="detail-loading" role="status" *ngIf="view.status==='loading'"><span class="loading-dot"></span>正在加载{{view.kind==='rule'?'规则详情':'事件详情'}}…</div>
  <div class="detail-error" role="alert" *ngIf="view.status==='error'"><h3>暂时无法加载</h3><p>{{view.error}}</p><button class="quiet" (click)="details.retry()">重新加载</button></div>
  <ng-container *ngIf="view.status==='ready'">
   <ng-container *ngIf="view.kind==='incident'">
    <div class="detail-actions"><div class="toolbar"><button (click)="investigate(view.data.incident)" [disabled]="investigating || !canInvestigate(view.data.incident)">{{investigating?'正在准备调查…':'调查关联事件 ↗'}}</button></div><div class="toolbar"><button class="quiet danger" [disabled]="!view.data.incident.src || banning" (click)="ban(view.data.incident.src)">封禁源地址</button><button class="quiet danger" [disabled]="!view.data.incident.dst || banning" (click)="ban(view.data.incident.dst)">封禁目的地址</button></div></div>
    <div class="incident-heading"><div class="detail-tags"><span class="badge" [class.danger]="view.data.incident.sev===1">{{sev(view.data.incident.sev)}}</span><span class="badge" [class.danger]="view.data.incident.action==='blocked'">{{act(view.data.incident.action)}}</span></div><h3>{{view.data.incident.sig}}</h3><p class="muted">{{dt(view.data.incident.first_ts)}} — {{dt(view.data.incident.last_ts)}}</p></div>
    <p class="muted" *ngIf="view.data.incident.session_id">会话 ID：{{view.data.incident.session_id}}</p><p class="muted" *ngIf="view.data.incident.tuple_hash">五元组关联键：{{view.data.incident.tuple_hash}}</p><div class="mini-stats"><div><small>告警</small><strong>{{view.data.incident.alert_count}}</strong></div><div><small>检测签名</small><strong>{{view.data.incident.signature_count}}</strong></div><div><small>关联网络日志</small><strong>{{view.data.incident.network_count}}</strong></div></div>
    <div class="path"><div><small>源地址</small><span>{{endpoint(view.data.incident.src,view.data.incident.sport)}}</span></div><b aria-hidden="true">→</b><div><small>目的地址</small><span>{{endpoint(view.data.incident.dst,view.data.incident.dport)}}</span></div></div>
    <ndr-attack-mapping [mapping]="view.data.attackMapping"/>
    <div ndrTabMotion class="tabs detail-tabs" role="tablist" aria-label="事件研判内容"><button role="tab" id="detail-tab-network" aria-controls="detail-panel-network" [attr.tabindex]="view.tab==='network'?0:-1" (keydown)="tabKey($event,view,'network')" [attr.aria-selected]="view.tab==='network'" [class.active]="view.tab==='network'" (click)="view.tab='network'">网络时间线 {{view.data.incident.network_count}}</button><button role="tab" id="detail-tab-alerts" aria-controls="detail-panel-alerts" [attr.tabindex]="view.tab==='alerts'?0:-1" (keydown)="tabKey($event,view,'alerts')" [attr.aria-selected]="view.tab==='alerts'" [class.active]="view.tab==='alerts'" (click)="view.tab='alerts'">告警证据 {{view.data.incident.alert_count}}</button><button role="tab" id="detail-tab-signatures" aria-controls="detail-panel-signatures" [attr.tabindex]="view.tab==='signatures'?0:-1" (keydown)="tabKey($event,view,'signatures')" [attr.aria-selected]="view.tab==='signatures'" [class.active]="view.tab==='signatures'" (click)="view.tab='signatures'">检测签名 {{view.data.incident.signature_count}}</button></div>
    <section animate.enter="section-enter" class="detail-section" role="tabpanel" id="detail-panel-signatures" aria-labelledby="detail-tab-signatures" *ngIf="view.tab==='signatures'"><h3>检测签名</h3><ndr-table id="incident-signatures" [columns]="signatureColumns" [rows]="view.data.incident.signatures" keyField="sid" [interactive]="true" (rowOpen)="details.rule($event)"/></section>
    <section animate.enter="section-enter" class="detail-section" role="tabpanel" id="detail-panel-alerts" aria-labelledby="detail-tab-alerts" *ngIf="view.tab==='alerts'"><h3>原始告警证据</h3><ndr-table id="incident-alerts" [columns]="eventColumns" [rows]="view.data.alerts" [interactive]="true" (rowOpen)="details.event($event)"/></section>
    <section animate.enter="section-enter" class="detail-section" role="tabpanel" id="detail-panel-network" aria-labelledby="detail-tab-network" *ngIf="view.tab==='network'"><h3>关联网络时间线</h3><p class="error" role="alert" *ngIf="view.networkError">{{view.networkError}}</p><ndr-table id="incident-network" [total]="view.data.incident.network_count" [offset]="view.data.network_offset || 0" [size]="view.data.network_limit || 50" [busy]="view.networkBusy" (pageChange)="details.networkPage($event)" [columns]="networkColumns" [rows]="view.data.network" [interactive]="true" (rowOpen)="details.event($event)"/></section>
   </ng-container>
   <ng-container *ngIf="view.kind==='rule'"><div class="detail-actions"><button (click)="investigateRule(view.data.sid,view.data.gid)">调查相关事件 ↗</button></div><section class="evidence-group"><h3>规则信息</h3><dl class="evidence-fields"><div class="wide"><dt>规则描述</dt><dd>{{view.data.msg || '手动规则'}}</dd></div><div><dt>规则编号（GID:SID）</dt><dd>{{view.data.gid||1}}:{{view.data.sid}}</dd></div><div><dt>实际动作</dt><dd>{{view.data.action || '—'}}</dd></div><div *ngIf="view.data.classtype"><dt>威胁分类</dt><dd>{{view.data.classtype}}</dd></div><div class="wide" *ngIf="view.data.origins?.length"><dt>规则来源</dt><dd><span *ngFor="let o of view.data.origins"><strong class="rule-source">{{o.source}}</strong> {{o.group}} </span></dd></div></dl></section><ndr-attack-mapping [mapping]="view.attackMapping" source="当前规则元数据"/><p class="muted" *ngIf="view.data.builtin"><strong class="rule-source">Snort 内置</strong> 检测签名，支持按签名或分组抑制告警。</p><section class="evidence-group" *ngIf="view.data.line"><div class="section-heading"><h3>规则原文</h3><button class="text-button" (click)="copy(view.data.line)">复制原文</button></div><pre>{{view.data.line}}</pre></section></ng-container>
   <ng-container *ngIf="view.kind==='event'"><div class="detail-actions"><div class="toolbar"><button [disabled]="investigating || !canInvestigate(view.record)" (click)="investigate(view.record)">{{investigating?'正在准备调查…':'调查关联事件 ↗'}}</button><button class="quiet" *ngIf="view.record.sig_id" (click)="details.rule(view.record)">检测规则</button></div><button class="quiet danger" [disabled]="!view.record.src || banning" (click)="ban(view.record.src)">封禁源地址</button></div>
    <div class="evidence-heading"><div class="detail-tags"><span class="badge">{{eventName(view.record.type)}}</span><span class="badge" *ngIf="view.record.action" [class.danger]="view.record.action==='blocked'">{{act(view.record.action)}}</span></div><h3><ndr-connection-summary *ngIf="view.record.type==='flow';else eventHeading" [record]="view.record" [wrap]="true"/><ng-template #eventHeading>{{view.record.sig || view.record.host || view.record.sni || view.record.dns || eventName(view.record.type)}}</ng-template></h3><p class="muted">{{dt(view.record.ts)}}</p></div>
    <ndr-attack-mapping [mapping]="view.attackMapping"/>
    <section class="evidence-group" *ngFor="let group of view.groups"><h3>{{group.title}}</h3><dl class="evidence-fields"><div *ngFor="let field of group.fields" [class.wide]="['sig','url','ua','answers','community'].includes(field.key)"><dt>{{field.label}}</dt><dd><ndr-connection-summary *ngIf="field.key==='sig'&&view.record.type==='flow';else evidenceFieldValue" [record]="view.record" [wrap]="true"/><ng-template #evidenceFieldValue><span [class.badge]="field.key==='state'&&view.record.type==='flow'" [class.flow-state]="field.key==='state'&&view.record.type==='flow'">{{field.value}}</span></ng-template></dd></div></dl></section>
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
   const range={choice:'custom',from:localDate(new Date(Number(result.from)*1000)),to:localDate(new Date(Number(result.to)*1000))};
   this.state.investigate(result.query,undefined,range);this.details.dismiss();
  }catch(error:any){if(this.details.current?.id===view?.id)this.state.toast(error.message);}
  finally{this.investigating=false;}
 }
 investigateRule(sid:any,gid:any=1):void{this.state.investigate('gid: '+gid+' AND sid: '+sid);this.details.dismiss();}
 async copy(value:string):Promise<void>{try{await navigator.clipboard.writeText(value);this.state.toast('已复制');}catch{this.state.toast('当前浏览器无法复制，请选中文本复制');}}
 copyJson(data:any,raw?:string):void{void this.copy(raw || JSON.stringify(data,null,2));}
 async ban(target:string):Promise<void>{if(!target||this.banning)return;if(!await this.state.confirm('封禁地址',target+' 将被加入封禁规则，确定继续？'))return;this.banning=true;try{const d=await this.api.post('/api/bans',{target});this.state.toast(d.message||'已提交封禁');}catch(e:any){this.state.toast(e.message);}finally{this.banning=false;}}
}
