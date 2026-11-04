import { CommonModule } from '@angular/common';
import { AfterViewInit, Component, ElementRef, EventEmitter, Input, OnChanges, Output, SimpleChanges, ViewChild, ChangeDetectionStrategy } from '@angular/core';
import { ConsoleState } from './core';
@Component({changeDetection:ChangeDetectionStrategy.Eager,selector:'ndr-modal',standalone:true,imports:[CommonModule],template:`<dialog #dialog animate.enter="dialog-enter" [class.drawer]="drawer" [class.wide]="wide" [attr.aria-label]="title+(titleSource?' '+titleSource:'')" (cancel)="$event.preventDefault();!busy && closed.emit()" (pointerdown)="backdropDown($event)" (pointerup)="backdropUp($event)" (pointercancel)="backdropStart=undefined"><div #scroll class="modal-scroll"><header class="modal-head"><div class="modal-title-group"><button *ngIf="canBack" class="quiet modal-back" (click)="back.emit()" [disabled]="busy">← 返回上一层</button><h2 tabindex="-1">{{title}}<ng-container *ngIf="titleSource">{{' '}}<strong class="rule-source">{{titleSource}}</strong></ng-container></h2></div><button class="icon-button" aria-label="关闭" [disabled]="busy" (click)="closed.emit()">✕</button></header><div class="modal-content"><ng-content></ng-content></div><div class="modal-notice" role="status" *ngIf="state.notice()">{{state.notice()}}<button class="icon-button" aria-label="关闭提示" (click)="state.notice.set('')">✕</button></div></div></dialog>`})
export class ModalComponent implements AfterViewInit,OnChanges {
 @Input() titleSource='';@Input() wide=false;@Input() title='';@Input() drawer=false;@Input() canBack=false;@Input() busy=false;@Input() viewKey:any;@Input() restoreScroll=0;
 @Output() back=new EventEmitter<void>();@Output() closed=new EventEmitter<void>();@ViewChild('dialog',{static:true}) dialog!:ElementRef<HTMLDialogElement>;@ViewChild('scroll',{static:true}) scroll!:ElementRef<HTMLDivElement>;
 backdropStart:{id:number;x:number;y:number}|undefined;
 private outside(event:PointerEvent):boolean{const dialog=this.dialog.nativeElement,r=dialog.getBoundingClientRect();return event.target===dialog&&(event.clientX<r.left||event.clientX>r.right||event.clientY<r.top||event.clientY>r.bottom);}
 backdropDown(event:PointerEvent):void{this.backdropStart=!this.busy&&event.button===0&&this.outside(event)?{id:event.pointerId,x:event.clientX,y:event.clientY}:undefined;}
 backdropUp(event:PointerEvent):void{const start=this.backdropStart;this.backdropStart=undefined;if(start&&start.id===event.pointerId&&!this.busy&&this.outside(event)&&Math.abs(start.x-event.clientX)<=6&&Math.abs(start.y-event.clientY)<=6)this.closed.emit();}
 constructor(public state:ConsoleState){}
 ngAfterViewInit():void{this.dialog.nativeElement.showModal();}
 ngOnChanges(changes:SimpleChanges):void{if(changes['viewKey']&&!changes['viewKey'].firstChange)queueMicrotask(()=>{const dialog=this.dialog.nativeElement;this.scroll.nativeElement.scrollTop=this.restoreScroll;dialog.querySelector<HTMLHeadingElement>('h2')?.focus({preventScroll:true});});}
}
