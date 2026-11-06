import { CommonModule } from '@angular/common';
import { Component, ElementRef, HostListener, OnDestroy, OnInit, ChangeDetectionStrategy } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Api, ConsoleState, LiveQuery, bytes, date } from '../core';
import { TableComponent, Column } from '../table.component';
@Component({changeDetection:ChangeDetectionStrategy.Eager,selector:'ndr-system',standalone:true,imports:[CommonModule,FormsModule,TableComponent],styles:[`
 .component-health dl { padding-top: 14px; }
 .component-health dt { align-self: start; color: var(--text); }
 .component-health dd { display: flex; align-items: baseline; justify-content: flex-end; flex-wrap: wrap; gap: 6px 12px; }
`],template:`
 <p class="error" role="alert" *ngIf="error">{{error}}</p><ng-container *ngIf="data as d;else loading">
 <section class="card component-health" *ngIf="d.components?.length"><header><h2>组件健康</h2><span *ngIf="componentProblems" class="badge danger">{{componentProblems}} 项需关注</span></header>
  <dl class="key-values"><ng-container *ngFor="let component of d.components;trackBy:trackComponent"><dt>{{component.name}}</dt><dd [attr.data-component]="component.id"><span class="badge" [class.good]="component.state==='ok'" [class.danger]="component.state==='error'">{{componentLabels[component.state] || '未读取'}}</span><span>{{component.message}}</span><small class="muted" *ngIf="component.range as range">{{time(range[0])}} 至 {{time(range[1])}}</small><small class="muted" *ngIf="component.at && !component.range">{{time(component.at)}}</small></dd></ng-container></dl>
 </section>
 <p class="muted telemetry-status" role="status" *ngIf="d.telemetry?.stale||d.telemetry?.updating">{{d.telemetry?.as_of?'引擎指标采样于 '+time(d.telemetry.as_of):'尚未取得引擎指标样本'}} <span class="badge">{{d.telemetry?.updating?'规则任务进行中':'等待新样本'}}</span></p><div class="system-grid"><section class="card" *ngFor="let section of sections;trackBy:trackSection"><header><h2>{{section.title}}</h2></header><dl class="key-values"><ng-container *ngFor="let pair of section.rows;trackBy:trackPair"><dt>{{pair[0]}}</dt><dd>{{pair[1]===null||pair[1]===undefined||pair[1]===''?'未读取':pair[1]}}</dd></ng-container></dl></section></div>
 <section class="card"><header><h2>日志文件</h2></header><ndr-table id="system-logs" [rows]="d.storage?.logs || []" [columns]="logColumns" keyField="name"/></section>
 <section class="card database-card" *ngIf="db"><header><h2>持久化事件库</h2><button class="quiet danger" (click)="clearDb()" [disabled]="clearing">清空历史事件</button></header><dl class="key-values"><dt>文件</dt><dd>{{db.path}}</dd><dt>大小 / 上限</dt><dd>{{memory(db.size)}} / {{memory(db.cap)}}</dd><dt>事件数</dt><dd>{{db.rows | number}}</dd><dt>最早事件</dt><dd>{{time(db.oldest)}}</dd><dt>最新事件</dt><dd>{{time(db.newest)}}</dd></dl><form class="db-capacity toolbar" (ngSubmit)="saveCapacity()"><label for="db-capacity">容量上限</label><input id="db-capacity" name="capacity" type="number" [min]="capacityUnit==='GiB'?db.min_cap_mib/1024:db.min_cap_mib" [max]="capacityUnit==='GiB'?db.max_cap_mib/1024:db.max_cap_mib" [step]="capacityUnit==='GiB'?'any':1" [(ngModel)]="capacity" (ngModelChange)="capacityError=''" [disabled]="savingCapacity" required><select name="capacity-unit" aria-label="容量单位" [ngModel]="capacityUnit" (ngModelChange)="changeCapacityUnit($event)" [disabled]="savingCapacity"><option value="MiB">MiB</option><option value="GiB">GiB</option></select><button type="submit" [disabled]="savingCapacity || !capacityChanged">{{savingCapacity?'保存中…':'保存'}}</button></form><p class="error" role="alert" *ngIf="capacityError">{{capacityError}}</p><p class="error" *ngIf="db.error">{{db.error}}</p></section><details class="card telemetry"><summary>原始引擎计数器</summary><pre>{{d.counters | json}}</pre></details></ng-container><ng-template #loading><div class="empty card">正在读取系统状态…</div></ng-template>
`})
export class SystemComponent implements OnInit,OnDestroy {
 data:any;db:any;error='';clearing=false;memory=bytes;time=date;private live:LiveQuery;capacity:number|null=null;capacityUnit:'MiB'|'GiB'='GiB';capacityError='';savingCapacity=false;private pending:any;private selecting=false;
 logColumns:Column[]=[{key:'name',label:'文件',width:320},{key:'size',label:'大小',kind:'bytes',width:160},{key:'mtime',label:'修改时间',kind:'time',width:220}];
 private dbLoaded=false;private alive=true;
 readonly componentLabels:Record<string,string>={ok:'正常',warning:'需关注',error:'异常',pending:'等待',idle:'按需'};
 constructor(private api:Api,private state:ConsoleState,private host:ElementRef<HTMLElement>){this.live=new LiveQuery(api,d=>{this.pending=d;this.applyPending();this.error='';if(this.dbLoaded)this.state.viewReady('system');},e=>{this.error=e;if(this.dbLoaded)this.state.viewReady('system');});}
 get componentProblems():number{return (this.data?.components||[]).filter((component:any)=>component.state==='error'||component.state==='warning').length;}
 trackComponent(_index:number,component:any):string{return component.id;}
 trackSection(_index:number,section:any):string{return section.title;}
 trackPair(_index:number,pair:any[]):string{return pair[0];}
 private hasSelection():boolean{const selection=window.getSelection();return !!selection&&!selection.isCollapsed&&!!selection.rangeCount&&selection.getRangeAt(0).intersectsNode(this.host.nativeElement);}
 private applyPending():void{if(this.pending&&!this.selecting&&!this.hasSelection()){this.data=this.pending;this.pending=undefined;}}
 @HostListener('pointerdown') startSelecting():void{this.selecting=true;}
 @HostListener('document:pointerup') endSelecting():void{this.selecting=false;this.applyPending();}
 @HostListener('document:pointercancel') cancelSelecting():void{this.selecting=false;this.applyPending();}
 @HostListener('document:selectionchange') selectionChanged():void{this.applyPending();}
 get capacityMib():number{return Number(this.capacity)*(this.capacityUnit==='GiB'?1024:1);}
 get capacityChanged():boolean{return this.capacity!==null&&this.capacityMib!==this.db?.cap/1048576;}
 changeCapacityUnit(unit:'MiB'|'GiB'):void{const mib=this.capacityMib;this.capacityUnit=unit;this.capacity=this.capacity===null?null:mib/(unit==='GiB'?1024:1);this.capacityError='';}
 async saveCapacity():Promise<void>{
  if(this.savingCapacity||!this.capacityChanged)return;
  const cap=this.capacityMib;
  if(this.capacity===null||!Number.isSafeInteger(cap)||cap<this.db.min_cap_mib||cap>this.db.max_cap_mib){this.capacityError='请输入 64 至 1048576 MiB（0.0625 至 1024 GiB），精确到整数 MiB。';return;}
  if(cap*1048576<this.db.size&&!await this.state.confirm('调低容量上限','新上限低于当前占用，后续自动回收会删除较早事件。确定保存？'))return;
  this.savingCapacity=true;this.capacityError='';
  try{const result=await this.api.post('/api/db/settings',{cap_mib:cap});this.db=result.stats;this.capacity=this.db.cap/(this.capacityUnit==='GiB'?1073741824:1048576);this.state.toast('容量上限已保存');}catch(e:any){this.capacityError=e.message;}finally{this.savingCapacity=false;}
 }
 get sections():any[]{const d=this.data||{},s=d.service||{},q=d.queue||{},e=d.engine||{},disk=d.storage?.disk||{};return [{title:'服务进程',tag:'SERVICE',rows:[['状态',s.state],['子状态',s.sub],['PID',s.pid],['运行秒数',s.uptime],['内存',bytes(s.memory)],['CPU 累计秒',s.cpu_seconds],['重启次数',s.restarts],['启动时间',s.since]]},{title:'检测引擎',tag:'ENGINE',rows:[['版本',e.version],...(e.error?[['读取错误',e.error]]:[]),['配置运行模式',e.running_mode],['配置采集方式',e.capture_mode],['运行秒数',e.uptime],['规则重载',d.reload?.state],['上次重载 ms',e.reload_time_ms??'引擎未提供'],[d.ruleset?.rules_loaded_source==='rule_files'?'配置文本规则':'生效文本规则',d.ruleset?.rules_loaded],['失败 / 跳过',(d.ruleset?.rules_failed??'未提供')+' / '+(d.ruleset?.rules_skipped??'未提供')]]},{title:'网络队列',tag:'NFQUEUE',rows:[['队列数',q.count],['入队包',q.packets],['积压',q.queue_total],['内核丢包',q.kernel_drops],['吞吐 pps',d.rates?.pps],['带宽 Mbps',d.rates?.mbps]]},{title:'存储与主机',tag:'STORAGE',rows:[['主机',d.host],['控制台版本',d.version],['日志分区',bytes(disk.used)+' / '+bytes(disk.total)],['可用空间',bytes(disk.free)],['控制台运行秒',d.uptime_web]]},{title:'引擎计数器',tag:'COUNTERS',rows:[['累计放行包',d.counters?.ips?.accepted],['累计阻断包',d.counters?.ips?.blocked],['拒绝动作次数',d.counters?.ips?.rejected],['规则阻断动作',d.counters?.ips?.drop_reason?.rules],['采集内核丢包',d.counters?.capture?.kernel_drops],['解码包数',d.counters?.decoder?.pkts],['流表内存',d.counters?.flow?.memuse==null?'引擎未提供':bytes(d.counters.flow.memuse)],['TCP 流模块内存',d.counters?.tcp?.memory==null?'引擎未提供':bytes(d.counters.tcp.memory)]]}];}
 ngOnInit():void{this.live.start('/api/system',{},'system');void this.loadDb();}
 async loadDb():Promise<void>{try{this.db=await this.api.get('/api/db/stats');if(this.capacity===null)this.capacity=this.db.cap/(this.capacityUnit==='GiB'?1073741824:1048576);}catch(e:any){this.state.toast(e.message);}finally{this.dbLoaded=true;if(this.data||this.error)this.state.viewReady('system');}}
 async clearDb():Promise<void>{
  if(this.clearing||!await this.state.confirm('清空历史事件','将暂停检测和采集，永久删除全部历史事件及尚未入库的原始日志，再重新启动。控制台会短暂断开，可能需要重新登录。规则和系统配置会保留。确定继续？'))return;
  this.clearing=true;
  try{
   const result=await this.api.post('/api/db/clear');
   if(result.pending){this.live.stop();this.state.toast('正在停止检测并清空历史，请等待服务恢复');await this.waitForReset(result.reset_id);}
   else {this.state.toast('历史事件已清空');await this.loadDb();}
  }catch(e:any){this.state.toast(e.message);if(this.alive)this.live.start('/api/system',{},'system');}finally{this.clearing=false;}
 }
 private async waitForReset(id:string):Promise<void>{
  const deadline=Date.now()+300000;
  while(Date.now()<deadline){
   await new Promise(resolve=>setTimeout(resolve,1000));
   let status:any;try{status=(await this.api.get('/api/db/clear/status')).reset;}catch{continue;}
   if(status.id!==id)continue;
   if(status.state==='failed')throw new Error(status.error||'历史清空失败，请检查服务状态');
   if(status.state==='done'){location.reload();return;}
  }
  throw new Error('等待服务恢复超时，请重新打开控制台检查清空任务状态');
 }
 ngOnDestroy():void{this.alive=false;this.live.stop();}
}
