import { ChangeDetectionStrategy, Component, Input, OnChanges } from '@angular/core';
import { CommonModule } from '@angular/common';
import { AttackEntry, AttackMapping } from './attack-mapping';

@Component({selector:'ndr-attack-mapping',standalone:true,imports:[CommonModule],changeDetection:ChangeDetectionStrategy.Eager,template:`
 <section class="evidence-group attack-mapping" *ngIf="mapping && (mapping.tactics.length || mapping.techniques.length)">
  <div class="section-heading"><h3>MITRE ATT&CK 攻击映射</h3><span class="muted">{{source}}</span></div>
  <p class="attack-intro">MITRE ATT&CK 是基于真实攻击行为的知识库；战术描述攻击目的，技术描述实施方式。</p>
  <dl class="attack-groups">
   <ng-container *ngFor="let group of groups;trackBy:trackGroup">
    <div *ngIf="group.items.length"><dt>{{group.label}}<span>{{group.hint}}</span></dt><dd>
     <details class="attack-entry" *ngFor="let entry of group.items;trackBy:trackEntry">
      <summary><span class="attack-code">{{entry.id}}</span><span>{{entry.name || '未收录名称'}}<small *ngIf="entry.retired">（已停用）</small></span><svg class="attack-chevron" viewBox="0 0 16 16" aria-hidden="true" focusable="false"><path d="M4 6 8 10 12 6" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg></summary>
      <div class="attack-description"><p *ngIf="entry.description" lang="en">{{entry.description}}</p><a [href]="entry.url" target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer">查看 MITRE 官方说明 ↗</a></div>
     </details>
    </dd></div>
   </ng-container>
  </dl>
 </section>
`})
export class AttackMappingComponent implements OnChanges {
 @Input() mapping:AttackMapping|null=null;
 @Input() source='告警元数据';
 groups:{label:string;hint:string;items:AttackEntry[]}[]=[];
 ngOnChanges():void{this.groups=this.mapping?[{label:'攻击战术',hint:'攻击目的',items:this.mapping.tactics},{label:'攻击技术',hint:'技术及子技术',items:this.mapping.techniques}]:[];}
 trackGroup=(_:number,group:{label:string})=>group.label;
 trackEntry=(_:number,entry:AttackEntry)=>entry.id;
}
