import { TabMotionDirective } from '../tab-motion.directive';
import { Component, OnDestroy, OnInit, ChangeDetectionStrategy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Api, ConsoleState, canonical, date,groupSelector,groupTarget,ruleSignature } from '../core';
import { TableComponent, Column, lastPageOffset } from '../table.component';
import { Details } from '../details.component';
import { PickerComponent } from '../picker.component';
import { SourceEditorComponent } from '../source-editor.component';
import { RuleEditorComponent } from '../rule-editor.component';
import { ModalComponent } from '../modal.component';
import { RuleCollectionComponent, RuleSelection, groupSelection } from '../rule-collection.component';
@Component({changeDetection:ChangeDetectionStrategy.Eager,selector:'ndr-rules',standalone:true,imports:[TabMotionDirective,CommonModule,FormsModule,TableComponent,PickerComponent,SourceEditorComponent,RuleEditorComponent,ModalComponent,RuleCollectionComponent],template:`
 <div class="rule-summary"><div class="stats-grid resource-summary rule-status-grid" role="group" aria-label="特征运行状态"><h2>特征概况</h2>
  <div class="stat-card rule-status-card"><span>{{summary?.ruleset?.rules_loaded_source==='rule_files'?'启用特征数':'已载入'}}</span><strong>{{!summary?'读取中':summary?.ruleset?.rules_loaded==null?'未提供':(summary.ruleset.rules_loaded | number)}}</strong></div>
  <div class="stat-card rule-status-card" [class.failed]="summary?.ruleset?.rules_failed>0"><span>失败</span><strong [attr.title]="summary&&summary?.ruleset?.rules_failed==null?'引擎未提供失败计数':null">{{!summary?'读取中':summary?.ruleset?.rules_failed==null?'未提供':(summary.ruleset.rules_failed | number)}}</strong></div>
  <div class="stat-card rule-status-card"><span>引擎状态</span><strong class="rule-engine-state" [class.is-ready]="summary&&!summary?.ruleset?.error&&!jobBusy&&summary?.reload?.state!=='running'&&summary?.reload?.ok!==false" [class.is-error]="summary?.ruleset?.error||summary?.reload?.ok===false">{{!summary?'读取中':summary?.ruleset?.error?'引擎状态不可用':(jobBusy||summary?.reload?.state==='running')?'特征校验与应用中':summary?.reload?.ok===false?'上次应用失败，请查看操作日志':'引擎就绪'}}</strong></div>
 </div></div>
 <div class="rule-navigation"><div ndrTabMotion class="tabs" role="tablist" aria-label="特征管理"><button *ngFor="let t of tabs;let i=index" role="tab" [id]="'rule-tab-'+t.id" [attr.aria-selected]="tab===t.id" [attr.tabindex]="tab===t.id?0:-1" [class.active]="tab===t.id" (click)="change(t.id)" (keydown)="tabKey($event,i)">{{t.title}}</button></div><div class="toolbar rule-actions"><button class="quiet" (click)="refreshCurrent()" [disabled]="busy">↻ 刷新</button><button (click)="job('apply')" [disabled]="jobBusy">应用更改 →</button></div></div>
 <div class="pending-rules warning" role="status" *ngIf="summary?.pending"><span>有待应用的更改，应用或更新特征后生效</span><button class="quiet" [disabled]="mutating||jobBusy" (click)="discardPending()">放弃待应用更改</button></div>
 <p class="error" *ngIf="error" role="alert">{{error}}</p>
 <div *ngIf="tab==='jobs'" role="tabpanel" aria-labelledby="rule-tab-jobs">
  <p class="error" role="alert" *ngIf="jobError">{{jobError}}</p>
  <ng-container *ngTemplateOutlet="jobOutput; context:{$implicit:latestJob,title:'特征操作日志'}"></ng-container>
  <section class="card" *ngIf="!latestJob"><header><h2>特征操作日志</h2></header><p class="muted empty">{{!jobStatus||busy?'正在读取操作日志…':'暂无手动操作日志'}}</p></section>
  <ng-container *ngTemplateOutlet="jobOutput; context:{$implicit:previousScheduledJob,title:'最近定时更新'}"></ng-container>
  <section class="card" *ngIf="!previousScheduledJob"><header><h2>最近定时更新</h2></header><p class="muted empty">{{!jobStatus||busy?'正在读取操作日志…':'暂无定时更新日志'}}</p></section>
 </div>
 <ng-template #jobOutput let-status let-title="title">
  <section class="card" *ngIf="status">
   <header><div><h2>{{title}}</h2><small class="muted" *ngIf="status.started">{{dt(status.started)}}</small></div><span class="badge">{{status.state==='running'?'执行中':status.rc==null?'已中断':'退出码 '+status.rc}}</span></header>
   <pre class="job-log" tabindex="0" [attr.aria-label]="title+'输出'" *ngIf="jobText(status);else noJobOutput">{{jobText(status)}}</pre>
   <ng-template #noJobOutput><p class="muted">{{status.state==='running'?'等待任务输出…':'没有命令输出'}}</p></ng-template>
  </section>
 </ng-template>
 <section class="card rules-list" *ngIf="tab!=='jobs'"><header><h2>{{title}}</h2><div class="toolbar">
  <button class="quiet" *ngIf="tab==='manual'" (click)="editor=true">＋ 手动特征</button><button *ngIf="['disable','action','suppress'].includes(tab)" (click)="openPicker(tab)">＋ 新建</button><button *ngIf="tab==='bans'" (click)="banModal=true">＋ 封禁</button>
  <button *ngIf="tab==='sources'" (click)="sourceEditor={source:null}">＋ 添加特征来源</button><button class="quiet" *ngIf="tab==='sources'" (click)="job('update')" [disabled]="jobBusy">更新特征集 ↗</button>
 </div></header>

 <div class="selection-bar" role="region" aria-label="已选特征操作" animate.enter="section-enter" *ngIf="selected.size"><span>已选 {{selected.size}}</span><div class="toolbar"><button class="text-button" (click)="selected=newSet()" [disabled]="mutating">取消选择</button><ng-container *ngIf="tab==='catalog'||tab==='groups'"><button class="quiet" [disabled]="directorySelection" (click)="openPicker('disable',selectionSeeds())">禁用</button><button class="quiet" [disabled]="nativeSelection" (click)="openPicker('action',selectionSeeds())">阻断动作</button><button class="quiet" (click)="openPicker('suppress',selectionSeeds())">抑制告警</button></ng-container><ng-container *ngIf="tab==='action'"><button class="quiet" (click)="changeActions('drop')" [disabled]="mutating">改为 drop</button><button class="quiet" (click)="changeActions('reject')" [disabled]="mutating">改为 reject</button><button class="quiet" [disabled]="selected.size!==1" (click)="editAction()">编辑</button></ng-container><ng-container *ngIf="tab==='sources'"><button class="quiet" (click)="editSource()" [disabled]="selected.size!==1">配置特征来源</button><button class="quiet" (click)="sourceBatch(true)" [disabled]="mutating">启用</button><button class="quiet" (click)="sourceBatch(false)" [disabled]="mutating">停用</button></ng-container><button *ngIf="['manual','disable','action','suppress','bans'].includes(tab)" class="quiet danger" (click)="remove()" [disabled]="mutating">{{tab==='bans'?'解封':'删除'}}</button></div></div>
 <p class="muted" *ngIf="nativeSelection">内置特征支持禁用和告警抑制；目录特征的加载与动作由配置管理。</p>
 <ndr-table [id]="'rules-'+tab" [columns]="columns" [rows]="rows" keyField="_key" [filterable]="true" [serverFilter]="tab==='catalog'" [filterMatch]="signatureFilter" [filterPlaceholder]="searchPlaceholder" [searchValue]="tab==='catalog'||membershipSearch?query:null" (searchValueChange)="updateSearch($event)" (searchRequested)="submitSearch($event)" [selectable]="true" [selected]="selected" (selectedChange)="selected=$event" [interactive]="true" (rowOpen)="openRow($event)" [total]="tab==='catalog'?total:null" [offset]="offset" [busy]="busy" (pageChange)="refresh(false,$event)"/>
 </section>
 <p class="muted" *ngIf="tab==='sources'&&summary?.sources_pending">特征来源更改待应用。“更新特征集”会下载特征并应用全部待应用更改；“应用更改”仅使用本地特征。校验成功后热重载，失败保留原特征。</p>
 <section class="card" *ngIf="tab==='sources'"><header><div><h2>定时更新</h2></div><span class="muted">路由器时区：{{schedule?.timezone}}</span></header><form (ngSubmit)="saveSchedule()" class="schedule-form" *ngIf="schedule"><fieldset [disabled]="scheduleSaving"><label class="checkbox-label"><input type="checkbox" name="enabled" [(ngModel)]="schedule.enabled">启用定时更新</label><label>频率<select name="frequency" [(ngModel)]="schedule.frequency"><option value="daily">每天</option><option value="weekly">每周</option></select></label><label *ngIf="schedule.frequency==='weekly'">星期<select name="weekday" [(ngModel)]="schedule.weekday"><option *ngFor="let day of weekdays;let i=index" [ngValue]="i">{{day}}</option></select></label><label>路由器本地时间<input name="time" type="time" required [(ngModel)]="schedule.time"></label><button type="submit">{{scheduleSaving?'保存中…':'保存计划'}}</button></fieldset></form><p class="muted">{{schedule?.enabled?'下次执行：'+schedule?.next_run_local:'定时更新已关闭'}} 最近执行：{{lastScheduledStart || '暂无'}}</p></section>
 <details class="card telemetry" *ngIf="tab==='manual'"><summary>系统本地特征（只读）</summary><pre>{{(summary?.local_rules || []).join('\n') || '暂无本地特征'}}</pre></details>
 <ndr-picker *ngIf="picker" [mode]="picker.mode" [seeds]="picker.seeds" [editing]="picker.editing" (closed)="picker=null" (saved)="selectionSaved($event)"/>
 <ndr-source-editor *ngIf="sourceEditor" [source]="sourceEditor.source" (closed)="sourceEditor=null" (saved)="selected=newSet();refresh()"/>
 <ndr-rule-editor *ngIf="editor" (closed)="editor=false" (saved)="refresh()"/>
 <ndr-modal *ngIf="banModal" title="新建封禁" [busy]="mutating" (closed)="!mutating && banModal=false"><form (ngSubmit)="ban()" class="form-stack"><label>IP 地址 / 域名<input name="target" aria-label="封禁目标" [(ngModel)]="banTarget" required placeholder="192.0.2.1 / example.com"></label><p class="error" *ngIf="banError">{{banError}}</p><footer class="modal-actions"><button type="button" class="quiet" [disabled]="mutating" (click)="banModal=false">取消</button><button [disabled]="mutating">确认封禁</button></footer></form></ndr-modal>
 <ndr-rule-collection *ngIf="selection" [selection]="selection" (closed)="selection=null"/>
`})
export class RulesComponent implements OnInit,OnDestroy {
 tabs=[{id:'catalog',title:'检测特征'},{id:'groups',title:'特征分组'},{id:'manual',title:'手动特征'},{id:'disable',title:'禁用策略'},{id:'action',title:'阻断动作'},{id:'suppress',title:'告警抑制'},{id:'bans',title:'封禁对象'},{id:'sources',title:'特征来源'},{id:'jobs',title:'操作日志'}];
 tab='catalog';summary:any;gov:any;rows:any[]=[];selected=new Set<string>();query='';offset=0;total=0;busy=false;error='';mutating=false;picker:any;editor=false;banModal=false;banTarget='';banError='';schedule:any;scheduleSaving=false;weekdays=['星期一','星期二','星期三','星期四','星期五','星期六','星期日'];selection:RuleSelection|null=null;
 jobStatus:any;jobError='';scheduledJob:any;lastScheduledStart='';dt=date;
 sourceEditor:any=null;
 get directorySelection():boolean{return this.rows.some(r=>this.selected.has(r._key)&&r.policy_managed===false&&!r.builtin);}
 policyLabel(value:string):string{return ({connectivity:'connectivity 优先连通性',balanced:'balanced 平衡检测',security:'security 优先安全','max-detect':'max-detect 最大检测覆盖'} as Record<string,string>)[value]||value||'—';}
 get nativeSelection():boolean{return this.rows.some(r=>this.selected.has(r._key)&&(r.builtin||r.policy_managed===false));}
 editSource():void{const source=this.rows.find(r=>this.selected.has(r._key));if(source&&(source.custom||source.requires_code))this.sourceEditor={source};}
 private revision=0;private pageRequest?:AbortController;private jobRequest?:AbortController;private pollTimer?:ReturnType<typeof setTimeout>;private refreshTimer?:ReturnType<typeof setInterval>;private alive=true;private startingJob=false;private refreshing=false;private catalogRows=new Map<string,any>();private appliedQuery='';
 private matching=new Set<string>();private searchTimer?:ReturnType<typeof setTimeout>;
 private jobLogs=new Map<string,{text:string;offset:number}>();
 private pageCache=new Map<string,{page:any;at:number}>();

 constructor(private api:Api,public state:ConsoleState,public details:Details){}
 get title():string{return this.tabs.find(t=>t.id===this.tab)?.title||'';}
 get membershipSearch():boolean{return this.tab==='groups'||this.tab==='sources';}
 get searchPlaceholder():string{return this.tab==='bans'?'':'GID:SID / SID / 名称';}
 signatureFilter=(query:string)=>{
  const signature=this.tab==='bans'?null:ruleSignature(query);
  if(!signature)return undefined;
  if(this.membershipSearch)return (row:any)=>query===this.appliedQuery&&this.matching.has(row._key);
  return (row:any)=>row.signature===signature.gid+':'+signature.sid;
 };
 updateSearch(query:string):void{
  this.query=query;clearTimeout(this.searchTimer);
  const normalized=query.trim().toLowerCase();
  if(this.membershipSearch&&ruleSignature(normalized)&&normalized!==this.appliedQuery)
   this.searchTimer=setTimeout(()=>void this.refresh(false,0,normalized),250);
 }
 submitSearch(query:string):void{
  clearTimeout(this.searchTimer);
  if(this.tab==='catalog')void this.refresh(false,0,query);
  else if(this.membershipSearch&&ruleSignature(query))void this.refresh(false,0,query.trim().toLowerCase());
 }
 get jobBusy():boolean{return this.startingJob||this.jobStatus?.state==='running';}
 get latestJob():any{return this.jobStatus?.state!=='idle'&&this.jobStatus?.trigger!=='scheduled'?this.jobStatus:this.jobStatus?.recent_manual;}
 get previousScheduledJob():any{
  return this.jobStatus?.trigger==='scheduled'?this.jobStatus:this.jobStatus?.recent_scheduled||this.scheduledJob;
 }
 jobText(status:any):string{return status.log_ref?this.jobLogs.get(status.log_ref)?.text||'':status.lines?.join('\n')||'';}
 private async loadJobLogs(signal:AbortSignal):Promise<void>{
  const logs=[this.latestJob,this.previousScheduledJob].filter(status=>status?.log_ref);
  const active=new Set(logs.map(status=>status.log_ref));
  for(const key of this.jobLogs.keys())if(this.jobLogs.size>4&&!active.has(key))this.jobLogs.delete(key);
  await Promise.all(logs.map(async status=>{
   const id=status.log_ref;
   let entry=this.jobLogs.get(id);if(!entry){entry={text:'',offset:0};this.jobLogs.set(id,entry);}
   const target=Number.isFinite(status.log_bytes)?status.log_bytes:Infinity;
   while(!signal.aborted&&entry.offset<target){
    const page=await this.api.get('/api/actions/log',{id,offset:entry.offset},signal);
    if(signal.aborted)return;
    if(page.id!==id||page.offset!==entry.offset||typeof page.text!=='string'||!Number.isInteger(page.next_offset)||page.next_offset<entry.offset)throw Error('操作日志分段无效');
    const previous=entry.offset;entry.text+=page.text;entry.offset=page.next_offset;
    if(page.eof||entry.offset===previous)break;
   }
  }));
 }
 get columns():Column[]{switch(this.tab){case 'catalog':return [{key:'signature',label:'GID:SID',width:130},{key:'msg',label:'特征描述',width:360},{key:'group',label:'特征分组',width:210},{key:'source',label:'特征来源',kind:'source',width:160},{key:'action',label:'实际动作',width:110}];case 'groups':return [{key:'name',label:'分组标识',width:240},{key:'label',label:'名称',width:230},{key:'source',label:'特征来源',kind:'source',width:160},{key:'total',label:'特征总数',width:110},{key:'compiled',label:'已启用',width:110},{key:'status',label:'状态',kind:'status',width:140}];case 'manual':return [{key:'sid',label:'SID',width:110},{key:'line',label:'特征原文',kind:'mono',width:740}];case 'sources':return [{key:'name',label:'特征来源',kind:'source',width:220},{key:'vendor',label:'提供者',width:140},{key:'summary',label:'说明',width:380},{key:'ipsPolicyLabel',label:'IPS 策略',width:220},{key:'license',label:'许可',width:120},{key:'authorization',label:'授权',width:100},{key:'status',label:'状态',kind:'status',width:100}];case 'bans':return [{key:'type',label:'类型',width:100},{key:'value',label:'封禁目标',width:280},{key:'ips',label:'解析 IP',width:370}];default:return [{key:'typeLabel',label:'类型',width:120},{key:'target',label:'匹配对象',kind:'scope',width:250},{key:'name',label:'名称',width:350},...(this.tab==='action'?[{key:'action',label:'目标动作',width:120}]:[]),...(this.tab==='suppress'?[{key:'status',label:'状态',kind:'status',width:140},{key:'memberCount',label:'成员数',width:100}]:[])];}}
 ngOnInit():void{const saved=this.state.views.get('rules');if(saved)Object.assign(this,saved);void this.refresh(false,this.offset,undefined,true);void this.pollJob();this.refreshTimer=setInterval(()=>{if(!document.hidden&&!this.mutating&&!this.picker&&!this.editor&&!this.sourceEditor&&!this.busy&&!this.jobBusy)this.refreshCurrent(true);},15000);}
 ngOnDestroy():void{this.state.views.set('rules',{tab:this.tab,query:this.query,appliedQuery:this.appliedQuery,offset:this.offset,selected:new Set(this.selected),pageCache:this.pageCache});this.alive=false;this.revision++;this.pageRequest?.abort();this.jobRequest?.abort();clearTimeout(this.pollTimer);clearTimeout(this.searchTimer);clearInterval(this.refreshTimer);}
 newSet():Set<string>{return new Set<string>();}
 change(tab:string):void{clearTimeout(this.searchTimer);this.tab=tab;this.offset=0;this.total=0;this.query='';this.appliedQuery='';this.selected=new Set();this.catalogRows.clear();this.rows=[];this.refreshCurrent(false,true);}
 refreshCurrent(background=false,reuse=false):void{void this.refresh(background,this.offset,undefined,reuse);if(this.tab==='jobs')void this.pollJob();}
 tabKey(event:KeyboardEvent,index:number):void{let i=index;if(event.key==='ArrowRight')i=(i+1)%this.tabs.length;else if(event.key==='ArrowLeft')i=(i+this.tabs.length-1)%this.tabs.length;else if(event.key==='Home')i=0;else if(event.key==='End')i=this.tabs.length-1;else return;event.preventDefault();this.change(this.tabs[i].id);const buttons=(event.currentTarget as HTMLElement).parentElement?.querySelectorAll<HTMLButtonElement>('button');buttons?.[i].focus();}
 async refresh(background=false,offset=this.offset,query=this.tab==='catalog'?this.appliedQuery:this.membershipSearch&&ruleSignature(this.query)?this.query.trim().toLowerCase():'',reuse=false):Promise<void>{if(!this.alive||background&&this.refreshing)return;const revision=++this.revision,tab=this.tab,key=JSON.stringify([tab,offset,query]);this.pageRequest?.abort();const request=this.pageRequest=new AbortController();this.busy=!background;this.refreshing=true;if(!background&&!reuse)this.pageCache.clear();const cached=reuse?this.pageCache.get(key):undefined;if(cached&&Date.now()-cached.at<30000){this.applyPage(cached.page,tab,offset,query);this.busy=false;this.state.viewReady('rules');}try{
  const page=await this.api.get('/api/rules/page',{
   tab:tab==='jobs'?'sources':tab,
   ...(query?{q:query}:{}),
   ...(tab==='catalog'?{limit:50,offset}:{}),
  },request.signal);
  if(revision!==this.revision)return;
  this.applyPage(page,tab,offset,query);
  if(revision!==this.revision)return;
  // The editable form needs the current schedule even when cached rows render first.
  if(tab==='sources'&&!this.schedule)this.schedule=page.schedule;
  if(this.pageCache.size>=12)this.pageCache.delete(this.pageCache.keys().next().value!);
  this.pageCache.set(key,{page,at:Date.now()});
 }catch(e:any){if(revision===this.revision&&e.name!=='AbortError')this.error='刷新失败，保留最近数据：'+e.message;}finally{if(revision===this.revision){this.pageRequest=undefined;this.busy=false;this.refreshing=false;this.state.viewReady('rules');}}}
 private applyPage(page:any,tab:string,offset:number,query:string):void{const {summary,governance:gov,data}=page;this.summary=summary;this.gov=gov;this.error='';
  if(page.schedule){this.scheduledJob=page.schedule.last_run;this.lastScheduledStart=page.schedule.last_started_local;}
  if(tab==='jobs')return;
  let rows:any[]=[];
  if(tab==='catalog'){const total=data.total||0,last=lastPageOffset(total);if(offset>last){void this.refresh(false,last,query);return;}rows=(data.rules||[]).map((r:any)=>({...r,_key:r.selector||'sid:'+r.sid,group:(r.origins||[]).map((o:any)=>o.group).join(', '),source:(r.origins||[]).map((o:any)=>o.source).join(', ')}));this.total=total;this.offset=offset;this.catalogRows=new Map([...this.catalogRows].filter(([key])=>this.selected.has(key)));rows.forEach(r=>this.catalogRows.set(r._key,r));}
  if(tab==='groups')rows=(data.groups||[]).filter((r:any)=>r.source_enabled!==false).map((r:any)=>({...r,_key:r.selector||groupSelector(r.name,r.source),status:r.compiled?'可用':'无已启用特征'}));
  if(tab==='manual')rows=(data.rules||[]).map((r:any)=>({...r,signature:r.sid?(r.gid||1)+':'+r.sid:'',_key:String(r.sid),_disabled:!r.sid}));
  if(tab==='bans')rows=(data.bans||[]).map((r:any)=>({...r,_key:r.value}));
  if(tab==='sources')rows=(data.sources||[]).map((r:any)=>({...r,_key:r.name,ipsPolicyLabel:!r.custom&&r.requires_code?this.policyLabel(r.ips_policy):'—',authorization:r.requires_code||r.custom?(r.credential_configured?'已配置':'未配置'):'无需',status:r.enabled?'已启用':'已停用'}));
  if(tab==='disable')rows=(gov.disable||[]).map((r:any)=>this.governanceRow(r,r.value));
  if(tab==='suppress')rows=[...(gov.suppress_groups||[]).map((r:any)=>({...this.governanceRow(r,r.selector),group_policy:true,status:'整组策略',memberCount:r.total})),...(gov.suppress||[]).map((r:any)=>({...this.governanceRow(r,'sid:'+(r.gid&&r.gid!==1?r.gid+':':'')+r.sid),_key:(r.gid&&r.gid!==1?r.gid+':':'')+r.sid,memberCount:1,status:r.pending?'待特征启用':summary?.rule_manager&&summary?.reload?.state==='running'?'待应用确认':summary?.reload?.ok===false?'应用失败':'已配置'}))];
  if(tab==='action'){const seen=new Set<string>();for(const r of gov.drop||[]){seen.add(canonical(r.value));rows.push({...this.governanceRow(r,r.value),source:'drop',action:r.reject?'reject':'drop'});}for(const r of gov.action||[]){if(!seen.has(canonical(r.selector)))rows.push({...this.governanceRow(r,r.selector),source:'action'});}}
  this.rows=rows;this.appliedQuery=query;this.matching=new Set(data.matching||[]);
 }
 governanceRow(row:any,value:string):any{const token=canonical(value),[type,...parts]=token.split(':'),id=ruleSignature(token);return {...row,_key:token,value:token,signature:id?id.gid+':'+id.sid:'',typeLabel:({sid:'SID',group:'特征分组','group-source':'特征分组',msg:'消息',re:'正则'} as any)[type]||type,target:type==='group-source'?groupTarget(token):parts.join(':'),targetName:type==='group-source'?decodeURIComponent(parts.slice(1).join(':')):parts.join(':'),targetSource:type==='group-source'?decodeURIComponent(parts[0]):''};}
 selectionSeeds():any[]{if(this.tab==='catalog')return [...this.selected].map(k=>({value:k,label:this.catalogRows.get(k)?.msg||k,source:this.catalogRows.get(k)?.source||''}));return this.rows.filter(r=>this.selected.has(r._key)).map(r=>({value:r.selector||groupSelector(r.name,r.source),label:r.name,source:r.source}));}
 openPicker(mode:string,seeds:any[]=[]):void{this.picker={mode,seeds,editing:false};}
 editAction():void{const row=this.rows.find(r=>this.selected.has(r._key));if(row)this.picker={mode:'action',seeds:[{value:row.value,label:row.name||row.targetName||row.target,source:row.targetSource||'',action:row.action}],editing:true};}
 openRow(row:any):void{
  if(this.tab==='sources'){
   this.selection={selector:'source:'+row.name,title:'特征集',source:row.name,metadata:[{label:'状态',value:row.status},{label:'说明',value:row.summary||'—'}]};return;
  }
  if(this.tab==='catalog'||this.tab==='manual'){void this.details.rule(row);return;}
  if(this.tab==='groups'){this.selection=groupSelection(row);return;}
  if(this.tab==='bans'){
   const target=String(row.value),quote=(v:any)=>JSON.stringify(String(v));
   const addresses=(row.ips||[]).flatMap((ip:string)=>['src: '+quote(ip),'dst: '+quote(ip)]);
   const clauses=row.type==='domain'?['dns: '+quote(target),'sni: '+quote(target),'host: '+quote(target),...addresses]:['src: '+quote(target),'dst: '+quote(target)];
   this.selection={selector:'ban:'+target,title:'封禁对象 '+target,query:'('+clauses.join(' OR ')+')',metadata:[{label:'类型',value:row.type==='domain'?'域名':'IP 地址'},{label:'封禁目标',value:target},{label:'解析 IP',value:(row.ips||[]).join(', ')||'—'}]};return;
  }
  const selector=this.tab==='suppress'&&!row.group_policy?'sid:'+(row.gid&&row.gid!==1?row.gid+':':'')+row.sid:row.value;
  this.selection={selector,title:this.title+' '+(row.targetName||row.target),source:row.targetSource||undefined,query:this.tab==='suppress'&&!row.group_policy?'gid: '+(row.gid||1)+' AND sid: '+row.sid:String(selector).startsWith('sid:')?selector:undefined,metadata:[{label:'匹配范围',value:row.targetName||row.target},...(row.targetSource?[{label:'特征来源',value:row.targetSource}]:[]),{label:'名称',value:row.name||'—'},...(this.tab==='action'?[{label:'目标动作',value:row.action}]:[]),...(this.tab==='suppress'?[{label:'配置状态',value:row.status}]:[])]};
 }
 private completeSelection(keys:string[],tab=this.tab):void{if(this.tab!==tab)return;const completed=new Set(keys.map(canonical));this.selected=new Set([...this.selected].filter(key=>!completed.has(canonical(key))));}
 selectionSaved(keys:string[]):void{this.completeSelection(keys);void this.refresh();}
 async sourceBatch(enable:boolean):Promise<void>{if(this.mutating||!this.selected.size)return;this.mutating=true;const errors:string[]=[],tab=this.tab,names=[...this.selected];try{for(const name of names){try{await this.api.post('/api/rules/source',{name,enable});this.completeSelection([name],tab);}catch(e:any){errors.push(name+': '+e.message);}}this.state.toast(errors.length?errors.join('；'):'特征来源更改已保存，点击“应用更改”生效');}finally{this.mutating=false;void this.refresh();}}
 async remove():Promise<void>{if(this.mutating||!await this.state.confirm(this.tab==='bans'?'解除封禁':'删除所选配置','确定处理选中的 '+this.selected.size+' 个对象？'))return;this.mutating=true;const errors:string[]=[];if(this.summary?.rule_manager){try{const paths=[...this.selected].map(key=>{const row=this.rows.find(r=>r._key===key);return (this.tab==='manual'?'/api/hunt/rules/':this.tab==='bans'?'/api/bans/':this.tab==='action'?'/api/rules/'+(row?.source==='action'?'action':'drop')+'/':this.tab==='suppress'&&row?.group_policy?'/api/rules/suppress-group/':'/api/rules/'+this.tab+'/')+encodeURIComponent(key);});await this.api.post('/api/rules/batch-delete',{paths});this.selected.clear();this.state.toast('已保存删除，点击“应用更改”生效');}catch(e:any){this.state.toast(e.message);}finally{this.mutating=false;void this.refresh();}return;}for(const key of [...this.selected]){const row=this.rows.find(r=>r._key===key);try{const path=this.tab==='manual'?'/api/hunt/rules/':this.tab==='bans'?'/api/bans/':this.tab==='action'?'/api/rules/'+(row?.source==='action'?'action':'drop')+'/':this.tab==='suppress'&&row?.group_policy?'/api/rules/suppress-group/':'/api/rules/'+this.tab+'/';await this.api.delete(path+encodeURIComponent(key));this.selected.delete(key);}catch(e:any){errors.push(key+': '+e.message);}}this.mutating=false;this.state.toast(errors.length?errors.join('；'):'已完成删除');void this.refresh();}
 async changeActions(action:string):Promise<void>{
  if(this.mutating||!this.selected.size)return;this.mutating=true;
  const tab=this.tab,rows=this.rows.filter(r=>this.selected.has(r._key)),errors:string[]=[];
  const batch=async(path:string,targets:any[],body:any)=>{if(!targets.length)return;try{
   const result=await this.api.request(path,'POST',body),failed:string[]=result.errors||[];
   if(result.ok===false&&!failed.length)throw new Error(result.message||'保存失败');
   this.completeSelection(targets.filter(row=>!failed.some(error=>error===row.value||error.startsWith(row.value+'（'))).map(row=>row._key),tab);
   errors.push(...failed);
  }catch(e:any){errors.push(e.message);}};
  try{const live=rows.filter(r=>r.source==='action'),deferred=rows.filter(r=>r.source==='drop');
   await batch('/api/rules/action',live,{selectors:live.map(r=>r.value),action,replace:true});
   await batch('/api/rules/reject',deferred,{values:deferred.map(r=>r.value),enable:action==='reject',replace:true});
   this.state.toast(errors.length?errors.join('；'):'动作已保存，点击“应用更改”生效');
  }finally{this.mutating=false;void this.refresh();}
 }
 async ban():Promise<void>{if(this.mutating)return;this.mutating=true;try{await this.api.post('/api/bans',{target:this.banTarget.trim()});this.banModal=false;this.banTarget='';this.banError='';this.state.toast('封禁已保存，点击“应用更改”生效');void this.refresh();}catch(e:any){this.banError=e.message;}finally{this.mutating=false;}}
 async discardPending():Promise<void>{if(this.mutating||!await this.state.confirm('放弃待应用更改','放弃所有待应用更改，恢复为当前生效配置？'))return;this.mutating=true;try{await this.api.post('/api/rules/pending/discard');this.state.toast('已恢复当前生效配置');void this.refresh();}catch(e:any){this.state.toast(e.message);}finally{this.mutating=false;}}
 async saveSchedule():Promise<void>{this.scheduleSaving=true;try{this.schedule=await this.api.post('/api/rules/schedule',{enabled:this.schedule.enabled,frequency:this.schedule.frequency,weekday:Number(this.schedule.weekday),time:this.schedule.time});this.state.toast('定时设置已保存');}catch(e:any){this.state.toast(e.message);}finally{this.scheduleSaving=false;}}
 async job(kind:string):Promise<void>{
  if(this.jobBusy||!this.alive)return;
  this.startingJob=true;
  try{
   await this.api.post('/api/actions/'+kind);
   if(!this.alive)return;
   this.jobStatus={kind,state:'running',lines:[]};
   this.jobError='';
   this.change('jobs');
  }catch(e:any){if(this.alive)this.state.toast(e.message);}
  finally{this.startingJob=false;}
 }
 async pollJob():Promise<void>{
  if(!this.alive)return;
  clearTimeout(this.pollTimer);
  this.jobRequest?.abort();
  const request=this.jobRequest=new AbortController();
  try{
   const status=await this.api.get('/api/actions/status',{},request.signal);
   if(request.signal.aborted)return;
   const wasRunning=this.jobStatus?.state==='running';
   this.jobStatus=status;
   this.jobError=status.log_error||'';
   if(status.state!=='running'&&wasRunning){
    this.state.toast(status.rc===0?'特征任务完成':'特征任务未完成，请查看操作日志');
    void this.refresh();
   }
   if(this.tab==='jobs')await this.loadJobLogs(request.signal);
   if(request.signal.aborted)return;
   if(status.state==='running')this.pollTimer=setTimeout(()=>void this.pollJob(),2000);
  }catch{
   if(request.signal.aborted)return;
   this.jobError='操作日志更新失败，正在重试';
   this.pollTimer=setTimeout(()=>void this.pollJob(),4000);
  }
 }
}
