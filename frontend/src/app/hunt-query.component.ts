import { CommonModule } from '@angular/common';
import { Component, ElementRef, EventEmitter, HostListener, Input, Output, ChangeDetectionStrategy } from '@angular/core';
import { HuntField, HuntSuggestion, huntSuggestions } from './hunt-fields';

@Component({changeDetection:ChangeDetectionStrategy.Eager,selector:'ndr-hunt-query',host:{'[class.suggestions-open]':'expanded'},standalone:true,imports:[CommonModule],template:`
 <label class="search"><span aria-hidden="true">⌕</span><input type="search" data-1p-ignore="true" spellcheck="false" autocapitalize="off" aria-label="搜索查询" role="combobox" aria-autocomplete="list" aria-controls="hunt-query-options" [attr.aria-expanded]="expanded" [attr.aria-activedescendant]="expanded && active>=0 ? 'hunt-option-'+active : null" autocomplete="off" placeholder="src:192.0.2.0/24 AND dport:443" [value]="value" (input)="update($any($event.target).value,$any($event.target).selectionStart)" (focus)="sync($event);open=true" (click)="sync($event);open=true" (keyup)="sync($event)" (keydown)="key($event)"></label>
 <div class="query-options" animate.enter="menu-enter" role="listbox" id="hunt-query-options" aria-label="查询字段与可选值" *ngIf="expanded"><div class="query-option-scroll">
  <button *ngFor="let field of suggestions;let i=index;trackBy:track" type="button" role="option" [id]="'hunt-option-'+i" [attr.aria-selected]="i===active" [class.active]="i===active" (mousedown)="$event.preventDefault()" (mouseenter)="active=i" (click)="choose(field)"><strong>{{field.example}}</strong><span>{{field.desc}}</span></button>
 </div></div>
`})
export class HuntQueryComponent {
 @Input() value='';@Input() fields:HuntField[]=[];@Output() valueChange=new EventEmitter<string>();open=false;active=-1;caret:number|null=null;
 constructor(private host:ElementRef<HTMLElement>){}
 get suggestions():HuntSuggestion[]{return huntSuggestions(this.value,this.fields,this.caret??this.value.length);}
 get expanded():boolean{return this.open&&this.suggestions.length>0;}
 track=(_:number,field:HuntSuggestion)=>field.example;
 sync(event:Event):void{const position=(event.target as HTMLInputElement).selectionStart;if(position!==this.caret){this.caret=position;this.active=-1;}}
 update(value:string,caret:number|null=null):void{this.value=value;this.caret=caret;this.valueChange.emit(value);this.open=true;this.active=-1;}
 choose(field:HuntSuggestion):void{this.value=this.value.slice(0,field.from)+field.example+this.value.slice(field.to);this.caret=field.from+field.example.length;this.valueChange.emit(this.value);this.open=false;this.active=-1;queueMicrotask(()=>{const input=this.host.nativeElement.querySelector('input');input?.focus();input?.setSelectionRange(this.caret,this.caret);});}
 key(event:KeyboardEvent):void{
  if(event.key==='Escape'){event.preventDefault();this.open=false;this.active=-1;return;}
  if(event.key==='ArrowDown'||event.key==='ArrowUp'){if(!this.suggestions.length)return;event.preventDefault();this.open=true;const count=this.suggestions.length;this.active=this.active<0?(event.key==='ArrowDown'?0:count-1):(this.active+(event.key==='ArrowDown'?1:-1)+count)%count;queueMicrotask(()=>this.host.nativeElement.querySelector('.query-options button.active')?.scrollIntoView({block:'nearest'}));}
  else if(event.key==='Enter'&&this.expanded&&this.active>=0){event.preventDefault();this.choose(this.suggestions[this.active]);}
  else if(event.key==='Tab'){this.open=false;this.active=-1;}
 }
 @HostListener('document:focusin',['$event.target']) focus(target:EventTarget|null):void{if(!(target instanceof Node)||!this.host.nativeElement.contains(target))this.open=false;}
 @HostListener('document:pointerdown',['$event.target']) outside(target:EventTarget|null):void{if(!(target instanceof Node)||!this.host.nativeElement.contains(target))this.open=false;}
}
