import { CommonModule } from '@angular/common';
import { Component, EventEmitter, Input, OnDestroy, OnInit, Output, ChangeDetectionStrategy } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Api, ConsoleState, canonical, groupSelector, groupTarget, ruleSignature } from './core';
import { Details } from './details.component';
import { ModalComponent } from './modal.component';
import { Column, TableComponent, lastPageOffset } from './table.component';
import { RuleCollectionComponent, RuleSelection, groupSelection } from './rule-collection.component';
import { RuleTargetComponent } from './rule-target.component';
@Component({changeDetection:ChangeDetectionStrategy.Eager,selector:'ndr-picker',standalone:true,imports:[CommonModule,FormsModule,ModalComponent,TableComponent,RuleTargetComponent,RuleCollectionComponent],styles:['.picker-toolbar { align-items: flex-end; }','.selected-target { display: inline-flex; align-items: center; min-width: 0; max-width: 100%; gap: 2px; } .selected-target .quiet { min-width: 0; }'],template:`
 <ndr-modal [busy]="busy" [title]="editing?'编辑阻断动作':titles[mode]" (closed)="!busy && closed.emit()"><fieldset class="picker-fields form-stack" [disabled]="busy"><div class="query-line picker-toolbar"><select aria-label="选择对象类型" [ngModel]="type" (ngModelChange)="changeType($event)" [disabled]="editing"><option value="sid">检测签名</option><option value="group">签名分组</option><option *ngIf="mode!=='suppress'" value="match">匹配条件</option></select><input type="search" autocomplete="off" data-1p-ignore="true" aria-label="搜索候选签名" class="grow" [(ngModel)]="query" (input)="debounce()" (keydown.enter)="search()" placeholder="GID:SID / SID / 名称 / 分组 / 签名来源" *ngIf="type!=='match'"><label *ngIf="mode==='action'">目标动作<select [(ngModel)]="action" aria-label="目标动作"><option>drop</option><option>reject</option></select></label></div>
 <div *ngIf="type==='match'" class="query-line"><select aria-label="匹配方式" [(ngModel)]="matchType"><option value="sid">SID</option><option value="group">分组匹配（所有来源）</option><option value="msg">消息</option><option *ngIf="mode==='action'" value="re">正则表达式</option></select><input aria-label="匹配值" [(ngModel)]="match" (keydown.enter)="addMatch()" placeholder="输入单条匹配条件"><button class="quiet" (click)="addMatch()">加入选择</button></div>
 <p class="error" role="alert" *ngIf="error">{{error}}</p><p class="muted" *ngIf="mode==='suppress'&&type==='group'">保存整组策略，签名更新后自动匹配新成员。同一 GID:SID 在各来源之间共享，抑制同时生效。</p>
 <p class="muted" *ngIf="mode==='disable'">按来源分组禁用仅影响所选来源，相同签名仍可能由其他来源生效。按 GID:SID 禁用会停用所有来源的该签名。</p>
 <ndr-table *ngIf="type!=='match'" id="picker-candidates" empty="暂无数据" [columns]="columns" [rows]="rows" keyField="value" [total]="total" [offset]="offset" [busy]="fetching" [selectable]="true" [interactive]="true" [selected]="selectedKeys" (selectedChange)="select($event)" (rowOpen)="openRow($event)" (pageChange)="page($event)"/>
 <section class="selection-panel"><div class="section-heading"><h3>已选 {{selected.size}}</h3><button class="text-button" (click)="selected.clear()" [disabled]="editing">清除</button></div><div class="chips"><span class="selected-target" *ngFor="let row of selected.values()"><button class="quiet" (click)="openRow(row)"><ndr-rule-target [name]="row.label || row.value" [source]="row.source || ''"/></button><button *ngIf="!editing" class="text-button" [attr.aria-label]="'移除 '+(row.label || row.value)" (click)="selected.delete(row.value)">×</button></span></div></section>
 <footer class="modal-actions"><button class="quiet" (click)="closed.emit()" [disabled]="busy">取消</button><button (click)="save()" [disabled]="busy || fetching || !selected.size">{{busy?'保存中…':'确认保存'}}</button></footer></fieldset></ndr-modal>
 <ndr-rule-collection *ngIf="selection" [selection]="selection" (closed)="selection=null"/>
`})
export class PickerComponent implements OnInit,OnDestroy {
 @Input() mode='disable';@Input() seeds:any[]=[];@Input() editing=false;@Output() closed=new EventEmitter<void>();@Output() saved=new EventEmitter<string[]>();
 titles:Record<string,string>={disable:'新增禁用策略',action:'新增阻断动作',suppress:'新增告警抑制'};
 type='sid';query='';offset=0;total=0;rows:any[]=[];selected=new Map<string,any>();action='drop';matchType='sid';match='';busy=false;fetching=false;error='';private generation=0;private timer?:ReturnType<typeof setTimeout>;private appliedQuery='';
 selection:RuleSelection|null=null;
 get columns():Column[]{return [{key:'target',label:'匹配对象',width:200},{key:'label',label:'签名名称 / 成员数',width:320},{key:'source',label:'签名来源',kind:'source',width:165},{key:'action',label:'当前动作',width:110}];}
 constructor(private api:Api,private state:ConsoleState,private details:Details){}
 get selectedKeys():Set<string>{return new Set(this.selected.keys());}
 ngOnInit():void{for(const row of this.seeds)this.selected.set(canonical(row.value),{...row,value:canonical(row.value)});if(this.editing){this.action=this.seeds[0]?.action||'drop';this.type='match';this.matchType=this.seeds[0]?.value?.split(':')[0]||'sid';}void this.search();}
 ngOnDestroy():void{this.generation++;clearTimeout(this.timer);}
 debounce():void{clearTimeout(this.timer);this.timer=setTimeout(()=>void this.search(),250);}
 changeType(type:string):void{this.type=type;this.offset=0;this.total=0;this.rows=[];this.appliedQuery='';void this.search();}
 page(offset:number):void{if(this.timer!==undefined)void this.search();else void this.search(offset,this.appliedQuery);}
 async search(offset=0,query=this.query):Promise<void>{clearTimeout(this.timer);this.timer=undefined;const generation=++this.generation;this.error='';if(this.type==='match'){this.fetching=false;return;}this.fetching=true;try{
  let rows:any[],total:number;
  if(this.type==='group'){
   const d=await this.api.get('/api/rules/groups',{q:query,exclude:this.mode});
   const list=d.groups||[];total=list.length;offset=Math.min(offset,lastPageOffset(total));
   rows=list.slice(offset,offset+50).map((r:any)=>({value:r.selector||groupSelector(r.name,r.source),target:r.name,
    label:this.mode==='suppress'?r.label+' '+r.total+' 条':r.label,source:r.source,group:r}));
  }else{const d=await this.api.get('/api/rules/search',{q:query,browse:1,limit:50,offset,exclude:this.mode});if(generation!==this.generation)return;total=d.total||0;const last=lastPageOffset(total);if(offset>last){void this.search(last,query);return;}rows=(d.rules||[]).map((r:any)=>({value:r.selector||'sid:'+r.sid,target:r.signature||r.selector||'sid:'+r.sid,label:r.msg,action:r.action,source:(r.origins||[]).map((o:any)=>o.source).join(', '),rule:r}));}
  if(generation===this.generation){this.rows=rows;this.total=total;this.offset=offset;this.appliedQuery=query;}
 }catch(e:any){if(generation===this.generation)this.error=e.message;}finally{if(generation===this.generation)this.fetching=false;}}
 select(keys:Set<string>):void{for(const r of this.rows){if(keys.has(r.value))this.selected.set(r.value,r);else this.selected.delete(r.value);}}
 openRow(row:any):void{
  const rule=row.rule||ruleSignature(row.value);
  if(rule){void this.details.rule(rule);return;}
  if(row.group){this.selection=groupSelection(row.group);return;}
  const group=/^group(-source)?:/.test(row.value);
  this.selection={selector:row.value,title:(group?'签名分组 ':'匹配签名 ')+(row.label||groupTarget(row.value)),source:row.source||undefined};
 }
 addMatch():void{try{const value=this.match.trim();if(!value||/[\r\n]/.test(value)||value.length>2000)throw new Error('请输入有效的单行匹配条件');if(this.matchType==='sid'&&(!/^\d+$/.test(value)||Number(value)<1||Number(value)>4294967295))throw new Error('SID 无效');const token=canonical(this.matchType+':'+value);this.selected.set(token,{value:token,label:value});this.match='';this.error='';}catch(e:any){this.error=e.message;}}
 async save():Promise<void>{if(this.busy)return;this.busy=true;this.error='';const errors:string[]=[],values=[...this.selected.keys()];
  let published=false;const publish=()=>{if(published)return;published=true;const completed=values.filter(value=>!this.selected.has(value));if(completed.length)this.saved.emit(completed);};
  const batch=async(path:string,values:string[],body:any)=>{if(!values.length)return;const r=await this.api.request(path,'POST',body);const failed:string[]=r.errors||[];if(r.ok===false&&!failed.length)throw new Error(r.message||'保存失败');for(const value of values){const token=this.mode==='suppress'?value.replace(/^sid:/,''):value;if(failed.some(s=>s===token||s.startsWith(token+'（')))continue;this.selected.delete(value);}errors.push(...failed);};
  try{
   if(this.mode==='disable')await batch('/api/rules/disable',values,{values});
   else if(this.mode==='suppress'){const groups=values.filter(v=>/^(group|group-source):/.test(v)),sids=values.filter(v=>v.startsWith('sid:')).map(v=>v.slice(4));if(groups.length){await this.api.post('/api/rules/suppress-groups',{groups,sids});this.selected.clear();}else await batch('/api/rules/suppress',values,{sids});}
   else{
    const gov=await this.api.get('/api/rules/governance');
    const prior=new Set((gov.drop||[]).map((r:any)=>canonical(r.value)));
    const update=values.filter(v=>prior.has(v));const deferred=values.filter(v=>!prior.has(v)&&/^(group|group-source|re):/.test(v));const live=values.filter(v=>!prior.has(v)&&/^(sid|msg):/.test(v));
    await batch('/api/rules/reject',update,{values:update,enable:this.action==='reject',replace:this.editing});
    await batch(this.action==='reject'?'/api/rules/reject':'/api/rules/drop',deferred,{values:deferred});
    await batch('/api/rules/action',live,{selectors:live,action:this.action,replace:this.editing});
   }
   publish();if(errors.length){const message=errors.join('；');await this.search(this.offset,this.appliedQuery);this.error=message;}else{this.state.toast('已保存，点击“应用更改”生效');this.closed.emit();}
  }catch(e:any){this.error=e.message;publish();}finally{this.busy=false;}
 }
}
