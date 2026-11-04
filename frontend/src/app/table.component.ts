import { CommonModule } from '@angular/common';
import { Component, ElementRef, EventEmitter, HostListener, Input, OnChanges, OnDestroy, Output, SimpleChanges, ChangeDetectionStrategy, afterEveryRender } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { action, bytes, date, severity } from './core';
import { engineAction, eventType } from './event-fields';
import { ConnectionSummaryComponent } from './connection-summary.component';
import { RuleTargetComponent } from './rule-target.component';
export interface Column {key:string;label:string;kind?:string;width?:number;}
@Component({changeDetection:ChangeDetectionStrategy.Eager,selector:'ndr-table',standalone:true,imports:[CommonModule,FormsModule,ConnectionSummaryComponent,RuleTargetComponent],template:`
  <form class="table-tools" *ngIf="filterable" (ngSubmit)="submitFilter()"><label class="search"><span>⌕</span><input type="search" name="filter" autocomplete="off" data-1p-ignore="true" [attr.aria-label]="serverFilter?'搜索规则签名':label+'搜索'" [placeholder]="serverFilter?'搜索规则全文 / 分组 / 源 / sid:编号':'搜索完整列表…'" [ngModel]="query" (ngModelChange)="updateFilter($event)"></label><button type="submit" [disabled]="busy">搜索</button></form>
  <div class="table-data"><div class="table-progress" *ngIf="busy" role="progressbar" aria-label="正在加载表格"><span></span></div>
  <div class="table-scroll" [attr.aria-busy]="busy"><table [style.min-width.px]="minimumWidth">
    <colgroup><col *ngIf="selectable" style="width:44px"><col *ngFor="let c of columns;let i=index;trackBy:trackColumn" [style.width.px]="fit && !widths.length ? (i===columns.length-1?64:null) : widths[i] || c.width || 150"><col *ngIf="interactive && showDetails" style="width:86px"></colgroup>
    <thead><tr><th *ngIf="selectable" class="check"><input type="checkbox" [attr.aria-label]="'选择当前页'" [checked]="allSelected" [indeterminate]="someSelected" (change)="selectPage($event)"></th>
      <th *ngFor="let c of columns;let i=index;trackBy:trackColumn">{{c.label}}<span class="resize" role="separator" tabindex="0" aria-orientation="vertical" [attr.aria-label]="'调整'+c.label+'列宽'" [attr.aria-valuenow]="widths[i] || c.width || 150" (pointerdown)="begin($event,i)" (keydown)="resizeKey($event,i)" (dblclick)="resetWidths()"></span></th><th *ngIf="interactive && showDetails" class="row-command">详情</th></tr></thead>
    <tbody><tr *ngFor="let row of visible;trackBy:track" [class.selected]="selected.has(key(row))" [class.clickable]="interactive" (click)="activate($event,row)" (keydown)="rowKey($event,row)" [attr.tabindex]="interactive?0:null">
      <td *ngIf="selectable" class="check" (click)="$event.stopPropagation()"><input type="checkbox" [attr.aria-label]="'选择 '+key(row)" [disabled]="row._disabled" [checked]="selected.has(key(row))" (change)="toggle(row,$event)"></td>
      <td *ngFor="let c of columns;trackBy:trackColumn" [class.mono]="c.kind==='mono'" [attr.title]="c.kind==='eventSummary'&&row.type==='flow'?null:format(row[c.key],c.kind)"><ndr-connection-summary *ngIf="c.kind==='eventSummary'&&row.type==='flow';else plainCell" [record]="row"/><ng-template #plainCell><ng-container [ngSwitch]="c.kind"><strong *ngSwitchCase="'source'" class="rule-source">{{format(row[c.key])}}</strong><ndr-rule-target *ngSwitchCase="'scope'" [name]="row.targetName || row[c.key]" [source]="row.targetSource || ''"/><ng-container *ngSwitchCase="'origins'"><ndr-rule-target *ngFor="let origin of row.origins" [name]="origin.group" [source]="origin.source"/> </ng-container><span *ngSwitchDefault [class.badge]="c.kind==='severity'||c.kind==='action'||c.kind==='status'" [class.danger]="c.kind==='severity'&&row[c.key]===1 || c.kind==='action'&&format(row[c.key],c.kind)==='已阻断'">{{format(row[c.key],c.kind)}}</span></ng-container></ng-template></td><td *ngIf="interactive && showDetails" class="row-command"><button class="text-button" aria-label="查看详情" (click)="$event.stopPropagation();activate($event,row)">查看 ↗</button></td></tr>
      <tr *ngIf="!visible.length"><td [attr.colspan]="columns.length+(selectable?1:0)+(interactive&&showDetails?1:0)" class="empty">{{busy?'正在加载…':empty}}</td></tr></tbody>
  </table></div></div>
  <div class="pager" *ngIf="pagination"><span>{{count | number}} 条 每页 {{size}} 条</span><div><button class="quiet" [disabled]="current===0 || busy" (click)="move(-1)">← 上一页</button><span>{{current+1}} / {{pageCount}}</span><button class="quiet" [disabled]="current+1>=pageCount || busy" (click)="move(1)">下一页 →</button></div></div>
`})
export class TableComponent implements OnChanges,OnDestroy {
  @Input() serverFilter=false;@Input() searchValue='';@Output() searchValueChange=new EventEmitter<string>();@Output() searchRequested=new EventEmitter<string>();@Input() fit=false;@Input() id='table';@Input() label='表格';@Input() columns:Column[]=[];@Input() rows:any[]=[];
  @Input() selectable=false;@Input() interactive=false;@Input() showDetails=true;@Input() filterable=false;@Input() pagination=true;@Input() busy=false;
  @Input() total:number|null=null;@Input() offset=0;@Input() size=50;@Input() keyField='id';@Input() empty='暂无数据';
  @Input() selected=new Set<string>();@Output() selectedChange=new EventEmitter<Set<string>>();@Output() rowOpen=new EventEmitter<any>();@Output() pageChange=new EventEmitter<number>();
  private static positions=new Map<string,{page:number;query:string}>();
  page=0;query='';widths:number[]=[];private dragging:{index:number;x:number;width:number}|null=null;
  private pageAnchor:number|null=null;
  constructor(private host:ElementRef<HTMLElement>){afterEveryRender(()=>this.positionPage());}
  private positionPage():void{
    if(this.pageAnchor===null||this.busy||(this.total!==null&&this.offset!==this.pageAnchor))return;
    const row=this.host.nativeElement.querySelector<HTMLElement>('tbody tr');if(!row)return;
    this.pageAnchor=null;
    const heading=this.host.nativeElement.querySelector('thead')?.getBoundingClientRect().height||0;
    let scroll:HTMLElement|null=row.parentElement,positioned=false;
    while(scroll){
      if(/auto|scroll/.test(getComputedStyle(scroll).overflowY)&&scroll.scrollHeight>scroll.clientHeight){
        const head=scroll.querySelector<HTMLElement>(':scope > .modal-head'),inset=heading+(head?.getBoundingClientRect().height||0);
        scroll.scrollTop+=row.getBoundingClientRect().top-scroll.getBoundingClientRect().top-scroll.clientTop-inset;positioned=true;
      }
      scroll=scroll.parentElement;
    }
    if(!positioned)window.scrollTo({top:window.scrollY+row.getBoundingClientRect().top-heading,behavior:'instant'});
  }
  ngOnChanges(changes:SimpleChanges):void {
    if(changes['id'])this.pageAnchor=null;
    if(changes['id']){const previous=changes['id'].previousValue;if(previous)TableComponent.positions.set(previous,{page:this.page,query:this.query});const saved=TableComponent.positions.get(this.id);this.page=saved?.page||0;this.query=saved?.query||'';try{this.widths=JSON.parse(localStorage.getItem('ndr.angular.columns.'+this.id)||'[]');if(!Array.isArray(this.widths)||!this.widths.every(n=>Number.isFinite(n)&&n>=64))this.widths=[];}catch{this.widths=[];}}
    if(this.serverFilter&&(changes['id']||changes['searchValue']))this.query=this.searchValue;
    if(this.total===null&&!this.busy){this.page=Math.min(this.page,this.pageCount-1);const valid=new Set(this.rows.filter(r=>!r._disabled).map(r=>this.key(r)));const next=new Set([...this.selected].filter(k=>valid.has(k)));if(next.size!==this.selected.size){this.selected=next;queueMicrotask(()=>this.selectedChange.emit(next));}}
  }
  updateFilter(value:string):void{this.query=value;this.page=0;if(this.serverFilter)this.searchValueChange.emit(value);}
  submitFilter():void{this.page=0;if(this.serverFilter)this.searchRequested.emit(this.query);}
  ngOnDestroy():void{TableComponent.positions.set(this.id,{page:this.page,query:this.query});}
  activate(event:Event,row:any):void{if(!this.interactive)return;const target=event.currentTarget as HTMLElement;const tr=target.tagName==='TR'?target:target.closest('tr');tr?.focus({preventScroll:true});this.rowOpen.emit(row);}
  rowKey(event:KeyboardEvent,row:any):void{if(event.target!==event.currentTarget||!['Enter',' '].includes(event.key))return;event.preventDefault();this.activate(event,row);}
  key(row:any):string{return String(row[this.keyField]??JSON.stringify(row));}
  track=(_:number,row:any)=>this.key(row);
  trackColumn=(_:number,column:Column)=>column.key;
  get filtered():any[]{if(this.serverFilter)return this.rows;const q=this.query.toLowerCase().trim();return q?this.rows.filter(r=>Object.values(r).join(' ').toLowerCase().includes(q)):this.rows;}
  get count():number{return this.total??this.filtered.length;}
  get current():number{return this.total!==null?Math.floor(this.offset/this.size):Math.min(this.page,this.pageCount-1);}
  get pageCount():number{return Math.max(1,Math.ceil(this.count/this.size));}
  get visible():any[]{return this.total!==null?this.rows:this.filtered.slice(this.current*this.size,(this.current+1)*this.size);}
  get allSelected():boolean {const rows=this.visible.filter(r=>!r._disabled);return !!rows.length&&rows.every(r=>this.selected.has(this.key(r)));}
  get someSelected():boolean{return !this.allSelected&&this.visible.some(r=>this.selected.has(this.key(r)));}
  get minimumWidth():number{if(this.fit&&!this.widths.length)return 0;return this.columns.reduce((n,c,i)=>n+(this.widths[i]||c.width||150),(this.selectable?44:0)+(this.interactive&&this.showDetails?86:0));}
  toggle(row:any,event:Event):void {const input=event.target as HTMLInputElement,checked=input.checked;const next=new Set(this.selected),key=this.key(row);checked?next.add(key):next.delete(key);this.selected=next;this.selectedChange.emit(next);}
  selectPage(event:Event):void {const input=event.target as HTMLInputElement,checked=input.checked;const next=new Set(this.selected);for(const row of this.visible.filter(r=>!r._disabled)){const k=this.key(row);checked?next.add(k):next.delete(k);}this.selected=next;this.selectedChange.emit(next);}
  move(delta:number):void {const next=Math.max(0,Math.min(this.pageCount-1,this.current+delta));if(next===this.current||this.busy)return;this.pageAnchor=next*this.size;if(this.total!==null)this.pageChange.emit(this.pageAnchor);else this.page=next;}
  format(v:any,kind?:string):string {if(v===null||v===undefined||v==='')return '—';if(kind==='eventType')return eventType(v);if(kind==='engineAction')return engineAction(v);if(kind==='time')return date(v);if(kind==='bytes')return bytes(v);if(kind==='severity')return severity(v);if(kind==='action')return action(v);if(Array.isArray(v))return v.join(', ');return String(v);}
  begin(event:PointerEvent,index:number):void {if(event.button!==0)return;event.preventDefault();(event.target as HTMLElement).setPointerCapture(event.pointerId);this.dragging={index,x:event.clientX,width:this.widths[index]||this.columns[index].width||150};}
  @HostListener('window:pointermove',['$event']) drag(event:PointerEvent):void {if(!this.dragging)return;this.widths[this.dragging.index]=Math.min(2400,Math.max(64,this.dragging.width+event.clientX-this.dragging.x));}
  @HostListener('window:pointerup') end():void {if(this.dragging){this.dragging=null;this.saveWidths();}}
  @HostListener('window:pointercancel') cancel():void {this.end();}
  resizeKey(event:KeyboardEvent,index:number):void {if(event.key==='Home'){this.resetWidths();return;}if(!['ArrowLeft','ArrowRight'].includes(event.key))return;event.preventDefault();this.widths[index]=Math.min(2400,Math.max(64,(this.widths[index]||this.columns[index].width||150)+(event.key==='ArrowRight'?1:-1)*(event.shiftKey?40:10)));this.saveWidths();}
  resetWidths():void {this.widths=[];localStorage.removeItem('ndr.angular.columns.'+this.id);}
  private saveWidths():void {try{localStorage.setItem('ndr.angular.columns.'+this.id,JSON.stringify(this.columns.map((c,i)=>this.widths[i]||c.width||150)));}catch{}}
}
