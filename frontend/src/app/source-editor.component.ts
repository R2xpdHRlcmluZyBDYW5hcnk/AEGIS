import {Component,Input,Output,EventEmitter,OnInit,ChangeDetectionStrategy} from '@angular/core';
import {CommonModule} from '@angular/common';
import {FormsModule} from '@angular/forms';
import {Api,ConsoleState} from './core';
import {ModalComponent} from './modal.component';

@Component({selector:'ndr-source-editor',standalone:true,imports:[CommonModule,FormsModule,ModalComponent],changeDetection:ChangeDetectionStrategy.Eager,styles:[`fieldset.form-stack{align-items:stretch;min-width:0}`],template:`
 <ndr-modal [title]="source?'配置特征来源':'添加特征来源'" [titleSource]="source?.name||''" [busy]="busy" (closed)="!busy&&closed.emit()">
 <form class="form-stack" (ngSubmit)="save()"><fieldset class="form-stack" [disabled]="busy">
 <ng-container *ngIf="custom;else official">
  <label>源标识<input name="slug" [(ngModel)]="slug" [disabled]="!!source" required pattern="[a-z0-9][a-z0-9_-]{0,63}" placeholder="例如 company-rules"></label>
  <label>显示名称<input name="label" [(ngModel)]="label" required maxlength="100"></label>
  <label>HTTPS 下载地址<input name="url" [(ngModel)]="url" type="url" [required]="!source" autocomplete="off" placeholder="https://example.com/snort3.rules"></label>
  <p class="muted" *ngIf="source">当前下载站点：{{source.download_host}}。地址留空则保留原地址。</p>
  <label>下载格式<select name="format" [(ngModel)]="format"><option value="rules">Snort 3 文本特征（.rules）</option><option value="tar.gz">包含 .rules 的归档（.tar.gz）</option></select></label>
  <label>Bearer 下载令牌（可选）<input name="token" type="password" [(ngModel)]="token" autocomplete="new-password" data-1p-ignore="true"></label>
 </ng-container>
 <ng-template #official><p>{{source?.name}}</p><label>Snort Oinkcode<input name="oinkcode" type="password" [(ngModel)]="oinkcode" autocomplete="new-password" data-1p-ignore="true" pattern="[0-9a-fA-F]{40}"></label><label>IPS 策略（Registered 与 LightSPD 共用）<select name="ips_policy" [(ngModel)]="policy"><option value="connectivity">connectivity 优先连通性</option><option value="balanced">balanced 平衡检测</option><option value="security">security 优先安全</option><option value="max-detect">max-detect 最大检测覆盖</option></select></label><label *ngIf="source?.name==='snort/registered'">Registered 快照版本（auto 自动匹配）<input name="version" [(ngModel)]="version" required pattern="auto|3\\.[0-9]+\\.[0-9]+\\.[0-9]+"></label><p class="muted">Registered 与 LightSPD 使用同一账户的 Oinkcode，仍需具备所选特征来源的访问权限。</p></ng-template>
 <p class="muted" *ngIf="source?.credential_configured">授权信息已配置，留空保留。保存后点击“应用更改”生效。</p>
 <label class="checkbox-label" *ngIf="source?.credential_configured"><input type="checkbox" name="clear" [(ngModel)]="clear">清除已保存的授权信息</label>
 <p class="muted" *ngIf="custom">支持多个官方源和自定义源同时启用。请使用兼容 Snort 3 的特征。出现冲突或校验失败时，当前特征继续生效。</p>
 <p class="error" role="alert" *ngIf="error">{{error}}</p>
 <footer class="modal-actions"><button type="button" class="quiet danger" *ngIf="source?.custom" (click)="remove()">删除特征来源</button><button type="button" class="quiet" (click)="closed.emit()">取消</button><button type="submit">{{busy?'保存中…':'保存'}}</button></footer>
 </fieldset></form></ndr-modal>
`})
export class SourceEditorComponent implements OnInit {
 @Input() source:any;@Output() closed=new EventEmitter<void>();@Output() saved=new EventEmitter<void>();
 custom=true;slug='';label='';url='';format='rules';token='';oinkcode='';version='auto';policy='balanced';clear=false;busy=false;error='';
 constructor(private api:Api,private state:ConsoleState){}
 ngOnInit():void{this.custom=!this.source||this.source.custom;this.slug=this.source?.name?.replace(/^custom\//,'')||'';this.label=this.source?.vendor||'';this.format=this.source?.format||'rules';this.version=this.source?.registered_version||'auto';this.policy=this.source?.ips_policy||'balanced';}
 async save():Promise<void>{if(this.busy)return;this.busy=true;this.error='';try{const name=this.source?.name||'custom/'+this.slug;await this.api.post('/api/rules/source/config',{name,...(this.custom?{label:this.label,url:this.url,format:this.format,token:this.token}:{oinkcode:this.oinkcode,registered_version:this.version,ips_policy:this.policy}),clear_credential:this.clear});this.token='';this.oinkcode='';this.state.toast('特征来源配置已保存，点击“应用更改”生效');this.saved.emit();this.closed.emit();}catch(e:any){this.error=e.message;}finally{this.busy=false;}}
 async remove():Promise<void>{if(!await this.state.confirm('删除特征来源','删除此自定义源，点击“应用更改”后从检测特征中移除？'))return;this.busy=true;this.error='';try{await this.api.post('/api/rules/source/config',{name:this.source.name,delete:true});this.saved.emit();this.closed.emit();}catch(e:any){this.error=e.message;}finally{this.busy=false;}}
}
