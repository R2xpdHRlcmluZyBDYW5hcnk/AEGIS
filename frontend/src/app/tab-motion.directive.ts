import { afterEveryRender, Directive, ElementRef, NgZone, OnDestroy, signal } from '@angular/core';

@Directive({selector:'[ndrTabMotion]',standalone:true,host:{
 class:'tab-motion',
 '[class.tab-keyboard]':'keyboard()',
 '(document:pointerdown)':'keyboard.set(false)',
 '(document:keydown)':'keyboardMode($event)',
 '[style.--tab-left]':'left()+"px"',
 '[style.--tab-width]':'width()+"px"'
}})
export class TabMotionDirective implements OnDestroy {
 readonly keyboard=signal(false);
 keyboardMode(event:KeyboardEvent):void{if(['Tab','ArrowLeft','ArrowRight','Home','End'].includes(event.key))this.keyboard.set(true);}
 readonly left=signal(0);
 readonly width=signal(0);
 private observer:ResizeObserver;
 constructor(private host:ElementRef<HTMLElement>,zone:NgZone){
  afterEveryRender({read:()=>this.measure()});
  this.observer=new ResizeObserver(()=>zone.run(()=>this.measure()));
  this.observer.observe(host.nativeElement);
 }
 private measure():void{
  const host=this.host.nativeElement;
  const active=host.querySelector<HTMLElement>('button[aria-selected="true"],button.active');
  if(!active){this.width.set(0);return;}
  const parent=host.getBoundingClientRect(),button=active.getBoundingClientRect();
  this.left.set(Math.round((button.left-parent.left+host.scrollLeft)*100)/100);
  this.width.set(Math.round(button.width*100)/100);
 }
 ngOnDestroy():void{this.observer.disconnect();}
}
