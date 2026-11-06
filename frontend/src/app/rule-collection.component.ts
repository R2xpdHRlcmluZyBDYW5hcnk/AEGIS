import { CommonModule } from '@angular/common';
import { ChangeDetectionStrategy, Component, EventEmitter, Input, OnChanges, OnDestroy, Output } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Api, ConsoleState, groupSelector } from './core';
import { Details } from './details.component';
import { ModalComponent } from './modal.component';
import { Column, TableComponent, lastPageOffset } from './table.component';

export interface RuleSelection {selector:string;title:string;source?:string;metadata?:{label:string;value:any}[];query?:string;}
export function groupSelection(row:{name:string;source:string;label?:string;selector?:string}):RuleSelection {
 return {selector:row.selector||groupSelector(row.name,row.source),source:row.source,title:'规则分组 '+row.name,
  metadata:row.label?[{label:'名称',value:row.label}]:[]};
}
@Component({changeDetection:ChangeDetectionStrategy.Eager,selector:'ndr-rule-collection',standalone:true,imports:[CommonModule,FormsModule,ModalComponent,TableComponent],template:`
 <ndr-modal [title]="selection.title" [titleSource]="selection.source||''" (closed)="closed.emit()">
  <dl class="evidence-fields selection-metadata"><div *ngFor="let field of selection.metadata"><dt>{{field.label}}</dt><dd><strong *ngIf="field.label==='规则源';else metadataValue" class="rule-source">{{field.value}}</strong><ng-template #metadataValue><span [class.badge]="field.label==='配置状态'||field.label==='目标动作'">{{field.value}}</span></ng-template></dd></div></dl>
  <div class="toolbar selection-actions" *ngIf="selection.query"><button class="quiet" (click)="investigate()">调查相关事件 ↗</button></div>
  <form (ngSubmit)="load(0,query)" class="query-line"><input type="search" autocomplete="off" data-1p-ignore="true" name="q" aria-label="搜索范围内规则" [(ngModel)]="query" placeholder="GID:SID / SID / 名称 / 规则原文"><button [disabled]="busy">搜索</button></form>
  <p class="error" role="alert" *ngIf="error">{{error}}</p>
  <ndr-table id="selection-rules" [rows]="rows" [columns]="columns" keyField="selector" [total]="total" [offset]="offset" [busy]="busy" [interactive]="true" empty="当前目录未找到匹配规则" (rowOpen)="details.rule($event)" (pageChange)="load($event)"/>
 </ndr-modal>
`})
export class RuleCollectionComponent implements OnChanges,OnDestroy {
 @Input({required:true}) selection!:RuleSelection;@Output() closed=new EventEmitter<void>();
 rows:any[]=[];total=0;offset=0;query='';busy=false;error='';private generation=0;private appliedQuery='';
 get columns():Column[]{return [{key:'signature',label:'GID:SID',width:130},{key:'msg',label:'规则描述',width:320},{key:'action',label:'目录动作',width:110},{key:'origin',label:'规则来源',kind:'origins',width:180},...(/^(group|group-source|source):/.test(this.selection.selector)?[{key:'status',label:'状态',kind:'status',width:100}]:[])];}
 constructor(private api:Api,public details:Details,private state:ConsoleState){}
 ngOnChanges():void{this.offset=0;this.query='';this.appliedQuery='';this.rows=[];this.total=0;void this.load(0);}
 async load(offset:number,query=this.appliedQuery):Promise<void>{const generation=++this.generation;this.busy=true;this.error='';try{
  const d=await this.api.get('/api/rules/selection',{selector:this.selection.selector,...(this.selection.source!==undefined?{source:this.selection.source}:{}),q:query,offset,limit:50});
  if(generation!==this.generation)return;if(d.error)throw new Error(d.error);
  const total=d.total||0,last=lastPageOffset(total);if(offset>last){void this.load(last,query);return;}
  this.rows=(d.rules||[]).map((r:any)=>({...r,status:r.enabled===false?'未启用':'已启用',origin:(r.origins||[]).map((o:any)=>[o.group,o.source].filter(Boolean).join(' ')).join(', ')}));this.total=total;this.offset=offset;this.appliedQuery=query;
 }catch(e:any){if(generation===this.generation)this.error=e.message;}finally{if(generation===this.generation)this.busy=false;}}
 investigate():void{if(this.selection.query){this.state.investigate(this.selection.query);this.closed.emit();}}
 ngOnDestroy():void{this.generation++;}
}
