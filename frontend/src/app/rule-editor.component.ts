import { CommonModule } from '@angular/common';
import { Component, EventEmitter, Output, ChangeDetectionStrategy } from '@angular/core';
import { FormArray, FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { Api, ConsoleState } from './core';
import { ModalComponent } from './modal.component';
@Component({changeDetection:ChangeDetectionStrategy.Eager,selector:'ndr-rule-editor',standalone:true,imports:[CommonModule,ReactiveFormsModule,ModalComponent],template:`
 <ndr-modal [busy]="saving" title="新建手动特征" (closed)="!saving && closed.emit()"><div class="segmented"><button [class.active]="mode==='guided'" (click)="mode='guided'">引导编辑</button><button [class.active]="mode==='raw'" (click)="toRaw()">特征原文</button></div>
 <form [formGroup]="form" (ngSubmit)="save()"><div *ngIf="mode==='guided'" class="form-stack"><div class="form-grid"><label>动作<select formControlName="action"><option *ngFor="let a of actions">{{a}}</option></select></label><label>协议<input formControlName="protocol" list="protocols"><datalist id="protocols"><option>tcp</option><option>udp</option><option>http</option><option>dns</option><option>ssl</option><option>ip</option><option>icmp</option></datalist></label></div>
 <label>特征描述<input formControlName="message" placeholder="说明该特征的检测目的"></label>
 <div class="rule-path"><label>源地址<input formControlName="src" placeholder="$HOME_NET"></label><label>源端口<input formControlName="sport"></label><label>方向<select formControlName="direction"><option>-></option><option>&lt;></option></select></label><label>目的地址<input formControlName="dst"></label><label>目的端口<input formControlName="dport"></label></div>
 <div class="section-heading"><h3>检测条件</h3><button type="button" class="quiet" (click)="addCondition()">＋ 条件</button></div><div formArrayName="conditions" class="form-stack"><div *ngFor="let condition of conditions.controls;let i=index" [formGroupName]="i" class="condition"><input formControlName="key" aria-label="检测关键字" placeholder="content / http_header" list="keywords"><input formControlName="value" aria-label="条件值" placeholder="无值选项留空"><button type="button" class="icon-button" aria-label="删除条件" (click)="conditions.removeAt(i)">✕</button></div></div>
 <datalist id="keywords"><option *ngFor="let k of keywords">{{k}}</option></datalist><p class="muted">按顺序设置 sticky buffer 和检测条件；content、pcre 自动补引号。</p>
 <label>附加选项<textarea formControlName="extra" rows="3" placeholder="flow:to_server,established;"></textarea></label><div class="form-grid"><label>分类<input formControlName="classtype" placeholder="可选"></label><label>严重度<select formControlName="severity"><option value="">自动</option><option value="1">1 高</option><option value="2">2 中</option><option value="3">3 低</option></select></label><label>SID<input formControlName="sid" placeholder="留空由服务端分配"></label><label>版本<input formControlName="rev" type="number" min="1"></label></div></div>
 <label *ngIf="mode==='raw'">完整特征<textarea class="code-input" formControlName="raw" rows="12" aria-label="特征原文" placeholder='alert tcp any any -> any any (msg:"Example"; content:"test";)'></textarea></label>
 <section class="preview"><h3>特征预览</h3><pre data-testid="rule-preview">{{preview}}</pre></section><p class="error" role="alert" *ngIf="error">{{error}}</p><footer class="modal-actions"><button type="button" class="quiet" [disabled]="saving" (click)="closed.emit()">取消</button><button type="submit" [disabled]="saving">{{saving?'保存中…':'保存待应用'}}</button></footer></form></ndr-modal>
`})
export class RuleEditorComponent {
 @Output() closed=new EventEmitter<void>();@Output() saved=new EventEmitter<void>();mode='guided';error='';saving=false;
 actions=['alert','block','drop','pass','reject','log'];keywords=['content','pcre','http_header','http_uri','http_method','http_stat_code','http_client_body','ssl_state','ssl_version','appids','flow','flags','dsize','detection_filter','byte_test','byte_jump','flowbits','stream_size','file_data','nocase','offset','depth','distance','within','fast_pattern'];
 form=this.fb.group({action:['alert',Validators.required],protocol:['tcp',Validators.required],message:['',Validators.required],src:['any',Validators.required],sport:['any',Validators.required],direction:['->'],dst:['any',Validators.required],dport:['any',Validators.required],extra:[''],classtype:[''],severity:[''],sid:[''],rev:['1'],raw:[''],conditions:this.fb.array<any>([])});
 constructor(private fb:FormBuilder,private api:Api,private state:ConsoleState){this.addCondition();}
 get conditions():FormArray{return this.form.controls.conditions;}
 addCondition():void{this.conditions.push(this.fb.group({key:[''],value:['']}));}
 private quote(value:string):string{return '"'+value.replace(/\\/g,'\\\\').replace(/"/g,'\\"')+'"';}
 build():string {
  const v:any=this.form.getRawValue();if(this.mode==='raw'){if(!v.raw.trim())throw new Error('请输入特征原文');return v.raw.trim();}
  const header=['action','protocol','src','sport','direction','dst','dport'].map(k=>{const x=String(v[k]||'').trim();if(!x||/[\s()]/.test(x))throw new Error('请完整填写特征头，各字段不能含空格或括号');return x;});
  if(!v.message.trim()||/[\r\n]/.test(v.message))throw new Error('请输入单行特征描述');
  const options=['msg:'+this.quote(v.message.trim())];
  for(const c of v.conditions){const k=c.key.trim();let val=c.value.trim();if(!k&&!val)continue;if(!/^[a-zA-Z_][a-zA-Z0-9_.]*$/.test(k))throw new Error('检测关键字格式无效');if(['content','pcre'].includes(k)&&val){const negated=val.startsWith('!'),text=negated?val.slice(1):val;if(!/^".*"$/.test(text))val=(negated?'!':'')+this.quote(text);}if(['nocase','offset','depth','distance','within','fast_pattern'].includes(k)){const index=options.length-1;if(index<0||!options[index].startsWith('content:'))throw new Error('内容修饰符须紧跟 content 条件');options[index]+=', '+k+(val?' '+val:'');}else options.push(k+(val?':'+val:''));}
  if(v.extra.trim())options.push(v.extra.trim().replace(/[\r\n]+/g,' ').replace(/;+$/,''));
  if(v.classtype){if(!/^[a-zA-Z0-9_-]+$/.test(v.classtype))throw new Error('分类格式无效');options.push('classtype:'+v.classtype);}
  if(v.severity)options.push('priority:'+v.severity);
  for(const k of ['sid','rev']){if(v[k]){if(!/^[1-9]\d*$/.test(String(v[k])))throw new Error(k+' 必须为正整数');options.push(k+':'+v[k]);}}
  return header.join(' ')+' ('+options.join('; ')+';)';
 }
 get preview():string{try{return this.build();}catch(e:any){return e.message;}}
 toRaw():void{if(this.mode==='guided'){try{this.form.controls.raw.setValue(this.build());}catch{}}this.mode='raw';}
 async save():Promise<void>{if(this.saving)return;try{const rule=this.build();this.saving=true;this.error='';const r=await this.api.post('/api/hunt/rules',{rule});this.state.toast(r.message||'特征已保存，请到特征管理点击“应用更改”');this.saved.emit();this.closed.emit();}catch(e:any){this.error=e.message;}finally{this.saving=false;}}
}
