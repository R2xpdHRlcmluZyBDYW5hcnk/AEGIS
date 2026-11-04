import { CommonModule } from '@angular/common';
import { ChangeDetectionStrategy, Component, Input } from '@angular/core';

@Component({selector:'ndr-rule-target',standalone:true,imports:[CommonModule],changeDetection:ChangeDetectionStrategy.Eager,template:`<span class="target-name" [title]="name">{{name}}</span><ng-container *ngIf="source">{{' '}}<strong class="rule-source">{{source}}</strong></ng-container>`,styles:[`:host{display:inline-flex;align-items:baseline;max-width:100%;min-width:0;gap:6px;vertical-align:middle}.target-name{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.rule-source{flex:0 0 auto}`]})
export class RuleTargetComponent {
 @Input() name='';@Input() source='';
}
