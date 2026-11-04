import { Component, effect, Input, OnDestroy, OnInit, ChangeDetectionStrategy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Api, ConsoleState, LiveQuery, date, localDate, timeRange } from '../core';
import { TableComponent, Column } from '../table.component';
import { RangeComponent } from '../range.component';
import { Details } from '../details.component';
import { RuleEditorComponent } from '../rule-editor.component';
import { HuntQueryComponent } from '../hunt-query.component';
import { completeHuntFields } from '../hunt-fields';
@Component({changeDetection:ChangeDetectionStrategy.Eager,selector:'ndr-events',standalone:true,imports:[CommonModule,FormsModule,TableComponent,RangeComponent,RuleEditorComponent,HuntQueryComponent],template:`
 <section class="card query-card"><div class="section-heading"><h2>{{mode==='hunt'?'事件查询':mode==='alerts'?'筛选安全事件':'筛选阻断记录'}}</h2><div class="toolbar"><button class="quiet" *ngIf="mode==='hunt'" (click)="editor=true">＋ 手动规则</button><button class="quiet" *ngIf="mode==='alerts'" (click)="exportCsv()">导出原始告警 CSV ↗</button></div></div>
 <form (ngSubmit)="search()"><div class="query-line"><ndr-hunt-query *ngIf="mode==='hunt'" class="grow" [value]="query" [fields]="fields" (valueChange)="query=$event"/><label *ngIf="mode!=='hunt'" class="search grow"><span>⌕</span><input type="search" autocomplete="off" data-1p-ignore="true" name="query" aria-label="搜索查询" [(ngModel)]="query" placeholder="签名、地址、端口或协议…"></label><select name="severity" aria-label="严重级别" [(ngModel)]="sev" *ngIf="mode==='alerts'"><option value="">全部级别</option><option value="1">高危</option><option value="2">中危</option><option value="3">低危</option></select><select name="protocol" aria-label="协议" [(ngModel)]="proto" *ngIf="mode!=='hunt'"><option value="">全部协议</option><option>TCP</option><option>UDP</option><option>ICMP</option></select><button type="submit" [disabled]="busy">{{busy?'查询中…':'查询 →'}}</button></div></form>
 <div class="filter-line"><ndr-range [sessionScope]="mode==='hunt'&&query.includes('session_id:')" [(choice)]="initialChoice" [(from)]="customFrom" [(to)]="customTo" (resetRequested)="resetFilters()" (changed)="setRange($event)"/><label class="checkbox-label"><input type="checkbox" [(ngModel)]="realtime" (ngModelChange)="load()">实时订阅</label><label class="checkbox-label" *ngIf="mode==='hunt'"><input type="checkbox" [(ngModel)]="caseSensitive" (ngModelChange)="search()">区分大小写</label></div>
 <details *ngIf="mode==='hunt'" class="syntax-help"><summary>查询语法与字段</summary><p>条件用 AND / OR / NOT 组合，支持引号、CIDR 和数值比较。点击字段示例加入查询。</p><div class="chips"><button class="quiet" *ngFor="let f of fields" (click)="query=(query?query+' AND ':'')+f.example" [title]="f.desc">{{f.example}}</button></div></details></section>
 <p class="error" role="alert" *ngIf="error">{{error}}</p><p class="warning" *ngIf="truncated">扫描达到上限，结果可能不完整，请缩小时间范围。</p>
 <div class="three-grid" *ngIf="mode==='drops' && aggregate"><section class="card" *ngFor="let top of dropTops"><header><h2>{{top.title}}</h2></header><ndr-table [id]="'drop-'+top.key" [columns]="top.columns" [rows]="aggregate[top.key] || []" [pagination]="false" [interactive]="true" [showDetails]="false" (rowOpen)="investigateDrop(top,$event)"/></section></div>
 <section class="card"><header><h2>{{mode==='alerts'?'事件调查队列':mode==='drops'?'阻断记录':'查询结果'}}</h2><span class="muted">{{total | number}} {{mode==='alerts'?'个事件':'条记录'}} {{realtime?'实时订阅':'手动查询'}}<span *ngIf="asOf"> 更新于 {{formatDate(asOf)}}</span></span></header><ndr-table [id]="mode" [columns]="columns" [rows]="rows" [total]="total" [offset]="offset" [busy]="busy" [interactive]="true" (pageChange)="offset=$event;load()" (rowOpen)="open($event)"/></section>
 <ndr-rule-editor *ngIf="editor" (closed)="editor=false"/>
`})
export class EventsComponent implements OnInit,OnDestroy {
 @Input() mode:'alerts'|'hunt'|'drops'='alerts';query='';sev='';proto='';caseSensitive=false;realtime=true;range:any={window:'1440'};initialChoice='1440';customFrom='';customTo='';rows:any[]=[];fields:any[]=[];total=0;offset=0;busy=false;error='';truncated=false;aggregate:any;editor=false;private live:LiveQuery;private generation=0;private queryKey='';private initialized=false;private seenInvestigation=0;private aggregateRevision=0;
 dropTops=[{key:'reasons',title:'阻断处置信息',columns:[{key:'reason',label:'处置动作或原因',kind:'engineAction',width:230},{key:'count',label:'次数',width:90}]},{key:'sources',title:'源地址',columns:[{key:'ip',label:'地址',width:200},{key:'count',label:'次数',width:90}]},{key:'destinations',title:'目的地址',columns:[{key:'ip',label:'地址',width:200},{key:'count',label:'次数',width:90}]}];
 private resolvingRange=false;private rangeRevision=0;
 asOf=0;formatDate=date;
 get columns():Column[]{return [{key:'ts',label:'时间',kind:'time',width:180},...(this.mode==='hunt'?[{key:'type',label:'类型',kind:'eventType',width:110}]:[{key:'sev',label:'级别',kind:'severity',width:90}]),{key:'summary',label:this.mode==='hunt'?'网络事件摘要':'检测签名',kind:'eventSummary',width:340},{key:'src',label:'源地址',kind:'mono',width:160},{key:'sport',label:'源端口',width:90},{key:'dst',label:'目的地址',kind:'mono',width:160},{key:'dport',label:'目的端口',width:100},{key:'proto',label:'协议',width:90},...(this.mode==='alerts'?[{key:'alert_count',label:'告警数',width:90},{key:'signature_count',label:'签名数',width:90}]:[]),{key:'action',label:'动作',kind:'action',width:100}];}
 constructor(private api:Api,public state:ConsoleState,private details:Details){effect(()=>{const revision=this.state.investigation();if(this.initialized&&this.mode==='hunt'&&revision!==this.seenInvestigation){this.applyInvestigation();this.search();}});this.live=new LiveQuery(api,d=>{this.rows=(d.incidents||d.events||[]).map((r:any)=>({...r,summary:r.sig||r.sni||r.dns||r.host||r.reason||r.type}));this.asOf=d.as_of||d.ts||0;this.total=d.total||0;this.truncated=!!d.truncated;this.error='';this.busy=false;if(this.mode!=='drops')this.state.viewReady(this.mode);if(this.mode==='drops')void this.loadAggregate(d.range);},e=>{this.error=e;this.busy=false;this.state.viewReady(this.mode);});}
 ngOnInit():void{const saved=this.state.views.get('events:'+this.mode);if(saved)Object.assign(this,saved);if(this.mode==='hunt'){if(!saved)this.realtime=false;if(!saved||saved.seenInvestigation!==this.state.investigation())this.applyInvestigation();void this.api.get('/api/hunt/schema').then(d=>this.api.zone.run(()=>this.fields=completeHuntFields(d.fields||[]))).catch(e=>this.state.toast(e.message));}this.initialized=true;this.load();}
 applyInvestigation():void{
  const revision=++this.rangeRevision;this.resolvingRange=false;this.seenInvestigation=this.state.investigation();this.query=this.state.huntQuery();this.sev='';this.proto='';
  const community=this.state.huntCommunity?.(),tuple=this.state.huntTuple?.();const flow=this.state.huntFlow(),time=this.state.huntTime(),selected=this.state.huntRange();this.initialChoice=selected?.choice||(flow||community||tuple||time?'custom':'1440');this.customFrom=selected?.from??time?.from??'';this.customTo=selected?.to??time?.to??'';this.range=selected?timeRange(selected.choice,selected.from,selected.to):time?timeRange('custom',time.from,time.to):{window:'1440'};
  if(selected?.choice==='all'&&this.query.includes('session_id:'))this.realtime=true;
  if(!flow&&!community&&!tuple)return;
  this.live.stop();this.rows=[];this.total=0;this.queryKey='';this.resolvingRange=true;this.busy=true;this.error='';
  void this.api.get(community?'/api/hunt/community-range':tuple?'/api/hunt/tuple-range':'/api/hunt/flow-range',community?{community}:tuple?{hash:tuple}:{flow}).then(bounds=>this.api.zone.run(()=>{
   if(revision!==this.rangeRevision||!this.initialized)return;
   this.customFrom=localDate(new Date(Number(bounds.from)*1000));this.customTo=localDate(new Date(Number(bounds.to)*1000));
   this.range=timeRange('custom',this.customFrom,this.customTo);this.resolvingRange=false;this.search();
  })).catch(error=>this.api.zone.run(()=>{
   if(revision!==this.rangeRevision||!this.initialized)return;
   this.resolvingRange=false;this.busy=false;this.error=error.message;this.state.viewReady(this.mode);
  }));
 }
 setRange(params:Record<string,string>):void{this.rangeRevision++;this.resolvingRange=false;this.range=params;this.search();}
 params():any{return {...this.range,q:this.query,sev:this.sev,proto:this.proto,limit:50,offset:this.offset,view:'list',...(this.mode==='hunt'?{icase:this.caseSensitive?'':'1'}:{}),...(this.mode==='drops'?{type:'drop'}:{})};}
 resetFilters():void{
  this.rangeRevision++;this.resolvingRange=false;this.query='';this.sev='';this.proto='';this.caseSensitive=false;this.realtime=this.mode!=='hunt';this.offset=0;this.truncated=false;
  if(this.mode==='hunt'){this.state.huntFlow.set(null);this.state.huntCommunity?.set(null);this.state.huntTuple?.set(null);this.state.huntRange.set(null);this.state.huntQuery.set('');this.state.huntTime.set(null);this.seenInvestigation=this.state.investigation();}
  this.state.views.delete('events:'+this.mode);
 }
 search():void{this.offset=0;this.load();}
 load():void{if(this.resolvingRange)return;this.generation++;this.aggregateRevision++;this.aggregateRequest?.abort();this.busy=true;this.error='';const params=this.params(),key=JSON.stringify(params);if(key!==this.queryKey){this.asOf=0;this.rows=[];this.total=0;this.aggregate=null;this.queryKey=key;}this.live.start(this.mode==='alerts'?'/api/incidents':this.mode==='drops'?'/api/events':'/api/hunt',params,this.realtime?this.mode:undefined);}
 private aggregateRequest?:AbortController;
 async loadAggregate(range:any):Promise<void>{this.aggregateRequest?.abort();if(!range){this.state.viewReady('drops');return;}const revision=++this.aggregateRevision,request=this.aggregateRequest=new AbortController();try{const params=this.params();delete params.window;const d=await this.api.get('/api/aggregate',{...params,from:range[0],to:range[1]},request.signal);if(revision===this.aggregateRevision)this.api.zone.run(()=>this.aggregate=d);}catch(e:any){if(revision===this.aggregateRevision&&e.name!=='AbortError')this.api.zone.run(()=>this.error=e.message);}finally{if(this.aggregateRequest===request)this.aggregateRequest=undefined;if(revision===this.aggregateRevision)this.api.zone.run(()=>this.state.viewReady('drops'));}}
 investigateDrop(top:any,row:any):void{
  const field=top.key==='reasons'?'reason':top.key==='sources'?'src':'dst',value=field==='reason'?row.reason:row.ip;
  if(value===null||value===undefined||value==='')return;
  const clauses=['type: drop',field+': '+JSON.stringify(String(value))];
  if(this.query.trim())clauses.push('('+this.query.trim()+')');
  if(this.proto)clauses.push('proto: '+JSON.stringify(this.proto));
  const range={choice:this.initialChoice,from:this.customFrom,to:this.customTo};
  this.state.investigate(clauses.join(' AND '),undefined,range);
 }
 open(row:any):void{if(this.mode==='alerts')void this.details.incident(row,this.range);else void this.details.event(row);}
 exportCsv():void{const p=new URLSearchParams({...this.params(),type:'alert',format:'csv',offset:'0',limit:'10000'});location.assign('/api/events?'+p);}
 ngOnDestroy():void{this.initialized=false;if(this.resolvingRange)this.state.views.delete('events:'+this.mode);else this.state.views.set('events:'+this.mode,{query:this.query,sev:this.sev,proto:this.proto,range:this.range,initialChoice:this.initialChoice,customFrom:this.customFrom,customTo:this.customTo,offset:this.offset,realtime:this.realtime,caseSensitive:this.caseSensitive,seenInvestigation:this.seenInvestigation});this.rangeRevision++;this.generation++;this.aggregateRevision++;this.aggregateRequest?.abort();this.live.stop();}
}
