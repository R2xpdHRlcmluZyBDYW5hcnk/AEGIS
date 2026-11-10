import { ModalComponent } from '../modal.component';
import { Component, OnDestroy, OnInit, ChangeDetectionStrategy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Api, ConsoleState, LiveQuery, bytes, date, localDate } from '../core';
import { ChartComponent } from '../chart.component';
import { ChartViewport } from '../chart-viewport';
import { TableComponent, Column } from '../table.component';
import { Details } from '../details.component';
import { eventType } from '../event-fields';
@Component({changeDetection:ChangeDetectionStrategy.Eager,selector:'ndr-overview',standalone:true,imports:[ModalComponent,CommonModule,ChartComponent,TableComponent],template:`
 <div class="overview-filters" *ngIf="filters.length" aria-label="概览筛选"><span>当前筛选</span><button class="quiet" *ngFor="let filter of filters" (click)="removeFilter(filter.key)" [attr.aria-label]="'移除筛选 '+filter.label">{{filter.label}} ×</button><button class="quiet" (click)="clearFilters()">清除筛选</button></div>
 <p *ngIf="error" class="error" role="alert">{{error}}</p>
 <div *ngIf="!data && !error" class="overview-loading" role="status" aria-label="正在加载概览" aria-busy="true" data-testid="overview-loading"><svg class="overview-spinner" viewBox="0 0 32 32" aria-hidden="true"><circle cx="16" cy="16" r="13"/></svg></div>
 <ng-container *ngIf="data as d"><div class="stats-grid resource-summary"><h2>检测概况</h2>
  <button class="stat-card alert" (click)="filterKind('alerts','检测告警')" [attr.aria-pressed]="hasKind('alerts')"><span>检测告警</span><strong data-testid="alerts-total">{{d.security?.alerts | number}}</strong></button>
  <button class="stat-card critical" (click)="filterKind('high','高危告警')" [attr.aria-pressed]="hasKind('high')"><span>高危告警</span><strong data-testid="high-total">{{d.security?.high | number}}</strong></button>
  <button class="stat-card blocked" (click)="filterKind('drops','阻断事件')" [attr.aria-pressed]="hasKind('drops')"><span>阻断事件</span><strong data-testid="drops-total">{{d.security?.drops | number}}</strong></button>
  <div class="stat-card"><span>源 / 目的地址</span><strong>{{d.network?.source_count | number}} <em>/ {{d.network?.destination_count | number}}</em></strong></div></div>
  <div class="overview-grid"><section class="card trend"><header><h2>告警与阻断趋势</h2><div class="toolbar"><div class="legend"><span class="blue-dot"></span>告警 <span class="coral-dot"></span>阻断</div><button class="quiet" (click)="showTrendTable=!showTrendTable" aria-label="切换趋势图表格">{{showTrendTable?'图表':'表格'}}</button><button class="quiet" (click)="expandedChart=true" aria-label="放大告警与阻断趋势">放大</button></div></header><ndr-chart *ngIf="!showTrendTable" [points]="d.series || []" [viewport]="chartViewport" (pointOpen)="filterTrend($event)"/><ndr-table *ngIf="showTrendTable" id="trend-values" [columns]="trendColumns" [rows]="d.series || []" [fit]="true"/></section>
  <section class="card engine-card"><header><h2>检测引擎</h2><span class="badge" [class.good]="d.service?.state==='active'">{{d.service?.state==='active'?'运行中':d.service?.state}}</span></header><div class="throughput">{{d.rates?.mbps | number:'1.2-2'}} <small>Mbps</small></div><p class="muted">{{d.rates?.pps | number:'1.0-0'}} packets / sec</p><dl class="key-values"><dt>已载入文本签名</dt><dd>{{d.rules?.loaded | number}}</dd><dt>内存占用</dt><dd>{{memory(d.service?.memory)}}</dd><dt>运行时长</dt><dd>{{d.service?.uptime | number}} 秒</dd><dt>NFQUEUE 积压</dt><dd data-testid="queue-backlog">{{(d.queue?.queue_total | number) ?? "未读取"}}</dd><dt>累计队列溢出丢包</dt><dd>{{(d.queue?.kernel_drops | number) ?? "未读取"}}</dd><dt>累计用户态投递丢包</dt><dd>{{(d.queue?.user_drops | number) ?? "未读取"}}</dd></dl></section></div>
  <ng-container *ngIf="d.network as n">
   <div class="section-heading visibility-heading"><h2>网络可见性</h2></div>
   <p [class.error]="!n.available" [class.muted]="n.available" [attr.role]="n.available?'status':'alert'" *ngIf="n.error && !networkRetrying(n)">{{n.error}}</p>
   <div class="stats-grid network-summary">
    <button class="stat-card" (click)="filterKind('connection','连接记录')" [attr.aria-pressed]="hasKind('connection')"><span>连接记录</span><strong>{{(n.flows | number) ?? '—'}}</strong></button>
    <div class="stat-card"><span>连接端点地址</span><strong>{{(n.addresses | number) ?? '—'}}</strong></div>
    <button class="stat-card" (click)="filterKind('dns','DNS 记录')" [attr.aria-pressed]="hasKind('dns')"><span>DNS 记录</span><strong>{{(n.dns | number) ?? '—'}}</strong></button>
    <button class="stat-card" (click)="filterKind('tls','TLS 记录')" [attr.aria-pressed]="hasKind('tls')"><span>TLS 记录</span><strong>{{(n.tls | number) ?? '—'}}</strong></button>
   </div>
  </ng-container>
  <div class="three-grid"><section class="card" *ngFor="let top of tops"><header><h2>{{top.title}}</h2><button class="quiet chart-view-toggle" (click)="top.table=!top.table" [attr.aria-label]="top.title+(top.table?'查看图表':'查看表格')">{{top.table?'图表':'表格'}}</button></header><ndr-chart *ngIf="!top.table" [ranks]="d.top?.[top.key] || []" [labelKey]="top.key==='signatures'?'sig':'ip'" [title]="top.title" (rowOpen)="filterTop(top,$event)"/><ndr-table *ngIf="top.table" [id]="top.key" [columns]="top.columns" [rows]="d.top?.[top.key] || []" [pagination]="false" [fit]="true" [interactive]="true" (rowOpen)="filterTop(top,$event)"/></section></div>
  <ng-container *ngIf="d.network as n">
   <ng-container *ngIf="n.available!==false">
   <div class="visibility-grid"><ng-container *ngFor="let top of networkTops"><section class="card" *ngIf="!n.partial || top.type!=='flow'"><header><h2>{{top.title}}</h2><button class="quiet chart-view-toggle" (click)="top.table=!top.table">{{top.table?'图表':'表格'}}</button></header><ndr-chart *ngIf="!top.table" [ranks]="n[top.key] || []" labelKey="name" [title]="top.title" (rowOpen)="filterNetwork(top,$event)"/><ndr-table *ngIf="top.table" [id]="'network-'+top.key" [columns]="networkColumns" [rows]="n[top.key] || []" [pagination]="false" [fit]="true" [interactive]="true" (rowOpen)="filterNetwork(top,$event)"/></section></ng-container></div>
   <div class="visibility-grid"><section class="card" *ngIf="!n.partial"><header><h2>高频连接源</h2></header><ndr-table id="network-sources" [columns]="sourceColumns" [rows]="n.sources || []" [pagination]="false" [fit]="true" [interactive]="true" (rowOpen)="filterConnectionSource($event)"/></section><section class="card"><header><h2>采集记录分布</h2><span class="muted">{{n.records | number}} 条记录</span></header><ndr-table id="network-types" [columns]="typeColumns" [rows]="n.event_types || []" [pagination]="false" [fit]="true" [interactive]="true" (rowOpen)="filterRecordType($event)"/><div class="capture-directions" *ngIf="!n.partial"><span>双向连接记录 <strong>{{n.bidirectional | number}}</strong></span><span>单向连接记录 <strong>{{n.one_way | number}}</strong></span></div></section></div>
   </ng-container>
   </ng-container>
  <section class="card"><header><h2>最新日志</h2></header><ndr-table id="recent" [columns]="recentColumns" [rows]="filterPending ? [] : (d.recent || []).slice(0,10)" [busy]="filterPending" [pagination]="false" [interactive]="true" (rowOpen)="details.event($event)"/></section>
  <details class="card telemetry engine-counters"><summary>累计引擎计数</summary><dl class="counter-grid"><div><dt>放行包</dt><dd>{{d.ips?.accepted | number}}</dd></div><div><dt>阻断包</dt><dd>{{d.ips?.blocked | number}}</dd></div><div><dt>签名触发丢包</dt><dd>{{d.ips?.rule_drops | number}}</dd></div><div><dt>引擎丢包</dt><dd>{{d.ips?.engine_drops | number}}</dd></div></dl></details>
 <ndr-modal *ngIf="expandedChart" title="告警与阻断趋势" [wide]="true" (closed)="expandedChart=false"><div class="chart-expanded"><ndr-chart [points]="d.series || []" [viewport]="chartViewport" (pointOpen)="filterTrend($event)"/></div></ndr-modal>
 </ng-container>
`,styles:[`
 .overview-loading{position:absolute;inset:0;display:grid;place-items:center;pointer-events:none}
 .overview-spinner{width:32px;height:32px;color:var(--green);animation:overview-spin 1.4s linear infinite}
 .overview-spinner circle{fill:none;stroke:currentColor;stroke-width:2.5;stroke-linecap:round;stroke-dasharray:1 82;animation:overview-arc 1.4s cubic-bezier(.4,0,.2,1) infinite}
 @keyframes overview-spin{to{transform:rotate(360deg)}}
 @keyframes overview-arc{0%{stroke-dasharray:1 82;stroke-dashoffset:0}50%{stroke-dasharray:60 82;stroke-dashoffset:-12}100%{stroke-dasharray:1 82;stroke-dashoffset:-82}}
 @media(prefers-reduced-motion:reduce){.overview-spinner,.overview-spinner circle{animation:none}.overview-spinner circle{stroke-dasharray:20 82}}
`]})
export class OverviewComponent implements OnInit,OnDestroy {
 filters:{key:string;label:string;params:Record<string,string>}[]=[];private period?:{from:number;to:number};
 data:any;expandedChart=false;showTrendTable=false;error='';filterPending=false;showingPrevious=false;refreshing=false;private displayedSelection='';private live:LiveQuery;memory=bytes;time=date;chartViewport=new ChartViewport();
 recentColumns:Column[]=[{key:'ts',label:'时间',kind:'time',width:180},{key:'type',label:'类型',kind:'eventType',width:110},{key:'sig',label:'网络事件摘要',kind:'eventSummary',width:340},{key:'src',label:'源地址',kind:'mono',width:160},{key:'dst',label:'目的地址',kind:'mono',width:160},{key:'proto',label:'协议',width:90},{key:'action',label:'动作',kind:'action',width:100}];
 tops=[{key:'signatures',title:'高频检测签名',field:'sid',table:false,columns:[{key:'sig',label:'签名',width:250},{key:'count',label:'次数',width:80}]},{key:'sources',title:'高频源地址',field:'src',table:false,columns:[{key:'ip',label:'地址',width:190},{key:'count',label:'次数',width:80}]},{key:'destinations',title:'高频目的地址',field:'dst',table:false,columns:[{key:'ip',label:'地址',width:190},{key:'count',label:'次数',width:80}]}];
 constructor(api:Api,public state:ConsoleState,public details:Details){
  const failed=(error:string)=>{this.error=error;this.filterPending=false;this.refreshing=false;this.state.viewReady('overview');};
  this.live=new LiveQuery(api,d=>{
   if(d.security?.error){failed('读取概览失败：'+d.security.error);return;}
   this.data=d;this.displayedSelection=this.selectionKey();this.error='';this.filterPending=false;this.showingPrevious=false;this.refreshing=false;this.state.viewReady('overview');
  },failed,null);
 }
 networkRetrying(network:any):boolean{
  // Existing servers send the timeout as text, together with the scheduled retry delay.
  return network.error==='网络统计更新失败：网络统计计算超时' && Number.isFinite(network.retry_seconds);
 }
 investigate(query:string):void{
  const range=this.data?.range;
  const local=(stamp:number)=>{
   const value=new Date(Math.round(stamp*1000));
   return localDate(value)+':'+String(value.getSeconds()).padStart(2,'0')+'.'+String(value.getMilliseconds()).padStart(3,'0');
  };
  this.state.investigate(query,undefined,range?{choice:'custom',from:local(range[0]),to:local(range[1])}:undefined);
 }
 networkTops=[{key:'applications',title:'连接应用分布',field:'app',type:'flow',table:false},{key:'protocols',title:'连接传输协议',field:'proto',type:'flow',table:false},{key:'dns_names',title:'高频 DNS 域名',field:'dns',type:'dns',table:false},{key:'tls_names',title:'高频 TLS 服务器名称',field:'sni',type:'tls',table:false}];
 trendColumns:Column[]=[{key:'t',label:'时间',kind:'time',width:180},{key:'alerts',label:'告警数',width:110},{key:'drops',label:'阻断数',width:110}];
 networkColumns:Column[]=[{key:'name',label:'名称',width:280},{key:'count',label:'记录数',width:90}];
 sourceColumns:Column[]=[{key:'ip',label:'源地址',width:200},{key:'count',label:'连接记录',width:100},{key:'bytes',label:'流量',kind:'bytes',width:110},{key:'latest',label:'最后出现',kind:'time',width:180}];
 typeColumns:Column[]=[{key:'name',label:'记录类型',kind:'eventType',width:180},{key:'count',label:'记录数',width:100}];
 investigateNetwork(top:any,row:any):void{this.investigate('type: '+top.type+' AND '+(row.name==='未识别'?'NOT '+top.field+': *':top.field+': '+JSON.stringify(row.name)));}
 investigateTop(top:any,row:any):void{
  if(top.key==='signatures'){
   if(row.sid){this.investigate('sid: '+row.sid);return;}
   if(row.sig)this.investigate((row.sig.startsWith('engine drop')?'type: drop AND ':'')+'sig: '+JSON.stringify(row.sig));
  }else if(row.ip)this.investigate(top.field+': '+JSON.stringify(row.ip));
 }
 ngOnInit():void{
  const saved=this.state.views?.get('overview');
  if(saved){this.data=saved.data;this.filters=saved.filters;this.period=saved.period;this.displayedSelection=saved.displayedSelection;this.showTrendTable=saved.showTrendTable;}
  if(this.data)this.state.viewReady('overview');
  this.refresh();
 }
 private selectionKey():string{return JSON.stringify({filters:this.filters,period:this.period});}
 filterKind(value:string,label:string):void{
  this.applyFilter('kind',label,['alerts','high','drops'].includes(value)?{detection:value}:value==='connection'?{connection:'1'}:{type:value});
 }
 hasKind(value:string):boolean{return this.filters.some(f=>f.key==='kind'&&(f.params['detection']===value||f.params['type']===value||(value==='connection'&&f.params['connection']==='1')));}
 private applyFilter(key:string,label:string,params:Record<string,string>):void{
  this.filters=[...this.filters.filter(f=>f.key!==key),{key,label,params}];this.refresh();
 }
 removeFilter(key:string):void{this.filters=this.filters.filter(f=>f.key!==key);if(key==='period')this.period=undefined;this.refresh();}
 clearFilters():void{this.filters=[];this.period=undefined;this.refresh();}
 filterTop(top:any,row:any):void{
  if(top.key==='signatures'){
   if(row.sid)this.applyFilter('signature','签名 '+row.sid,{sid:String(row.sid)});
   else if(row.sig)this.applyFilter('signature',row.sig,{sig:row.sig});
  }else if(row.ip)this.applyFilter(top.field,(top.field==='src'?'源地址 ':'目的地址 ')+row.ip,{[top.field]:row.ip});
 }
 filterNetwork(top:any,row:any):void{
  const params=row.name==='未识别'?{['missing_'+top.field]:'1'}:{[top.field]:row.name};
  this.applyFilter(top.field,top.title+' '+row.name,params);
 }
 filterConnectionSource(row:any):void{this.applyFilter('src','连接源 '+row.ip,{src:row.ip,connection:'1'});}
 filterRecordType(row:any):void{this.filterKind(row.name,eventType(row.name)+' 相关会话');}
 filterTrend(event:{point:{t:number};kind:'alerts'|'drops'}):void{
  const step=Number(this.data?.bucket)*60,range=this.data?.range;
  if(!step||!range||!Number.isFinite(event.point.t))return;
  const from=Math.max(range[0],event.point.t),to=Math.min(range[1],event.point.t+step-.001);
  if(to<from)return;
  this.period={from,to};this.expandedChart=false;
  this.filters=this.filters.filter(f=>f.key!=='kind'&&f.key!=='period');
  this.filters.push({key:'period',label:date(from)+' 至 '+date(to),params:{}});
  this.filterKind(event.kind,event.kind==='alerts'?'检测告警':'阻断事件');
 }
 private refresh():void{
  const selected:Record<string,string>={scope:'cache'};
  if(this.period){
   selected['from']=String(this.period.from);
   selected['to']=String(this.period.to);
  }
  for(const filter of this.filters)Object.assign(selected,filter.params);
  this.chartViewport.reset();this.showingPrevious=!!this.data;this.filterPending=this.data?this.displayedSelection!==this.selectionKey():this.filters.length>0;this.refreshing=true;
  this.error='';this.live.start('/api/overview',{...selected,view:'panel'},'overview');
 }
 ngOnDestroy():void{
  this.state.views?.set('overview',{data:this.data,filters:this.filters.map(f=>({...f,params:{...f.params}})),period:this.period?{...this.period}:undefined,displayedSelection:this.displayedSelection,showTrendTable:this.showTrendTable});
  this.live.stop();
 }
}
