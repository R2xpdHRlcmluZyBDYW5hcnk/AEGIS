import { Component, Input, OnChanges, ChangeDetectionStrategy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { connectionSummary } from './event-fields';

@Component({changeDetection:ChangeDetectionStrategy.Eager,selector:'ndr-connection-summary',standalone:true,imports:[CommonModule],host:{'[class.wrap]':'wrap'},template:`
 <span class="summary-text" [title]="summary.text">{{summary.text}}</span>
 <span *ngIf="summary.state" class="badge flow-state" [attr.aria-label]="'连接状态：'+summary.state" [title]="'连接状态：'+summary.state">{{summary.state}}</span>
 <span *ngIf="summary.details" class="summary-details" [title]="summary.details">{{summary.details}}</span>
`,styles:[`
 :host{display:inline-flex;align-items:center;gap:8px;max-width:100%;min-width:0;vertical-align:middle}
 .summary-text{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
 .flow-state{flex:0 0 auto}
 .summary-details{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
 :host(.wrap){flex-wrap:wrap}
 :host(.wrap) .summary-text{white-space:normal;overflow-wrap:anywhere}
 :host(.wrap) .summary-details{white-space:normal;overflow-wrap:anywhere}
`]})
export class ConnectionSummaryComponent implements OnChanges {
 @Input() record:Record<string,any>={};@Input() wrap=false;
 summary={text:'',state:'',details:''};
 ngOnChanges():void{this.summary=connectionSummary(this.record);}
}
