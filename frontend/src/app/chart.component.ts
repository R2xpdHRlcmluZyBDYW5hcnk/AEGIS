import { CommonModule } from '@angular/common';
import { AfterViewInit, ChangeDetectionStrategy, ChangeDetectorRef, Component, DoCheck, ElementRef, EventEmitter, Input, NgZone, OnChanges, OnDestroy, Output, ViewChild } from '@angular/core';
import type { EChartsType } from 'echarts/core';
import { ChartViewport, TrendPoint } from './chart-viewport';
import { ChartPalette, defaultPalette, rankOptions, trendOptions } from './chart-options';

@Component({changeDetection:ChangeDetectionStrategy.Eager,selector:'ndr-chart',standalone:true,imports:[CommonModule],template:`
 <div class="chart-wrap" [class.rank-chart]="ranks!==null">
  <div #surface class="echarts-surface" [style.height.px]="ranks!==null?Math.max(220,ranks.length*32+40):null" role="img" [attr.aria-label]="ranks!==null?title+'，点击排行筛选概览':'告警与阻断趋势，点击柱形筛选，可滚轮缩放、按住鼠标左右拖动'"></div>
  <div class="chart-empty" *ngIf="error" role="alert"><span>{{error}} <button class="quiet" (click)="load()">重试</button></span></div>
  <div class="chart-empty" *ngIf="!loading && !error && ranks!==null && !ranks.length">暂无数据</div>
  <button *ngIf="ranks===null && viewport.zoomed" class="quiet chart-zoom-reset" (click)="resetZoom()">重置缩放</button>
 </div>
`})
export class ChartComponent implements AfterViewInit,OnChanges,DoCheck,OnDestroy {
 @Input() points:TrendPoint[]=[];@Input() viewport=new ChartViewport();
 @Input() ranks:any[]|null=null;@Input() labelKey='sig';@Input() title='';
 @Output() rowOpen=new EventEmitter<any>();@Output() pointOpen=new EventEmitter<{point:TrendPoint;kind:'alerts'|'drops'}>();@ViewChild('surface',{static:true}) surface!:ElementRef<HTMLElement>;
 Math=Math;loading=false;error='';private destroyed=false;private chart?:EChartsType;private observer?:ResizeObserver;private seenRevision=-1;private updating=false;
 constructor(private zone:NgZone,private change:ChangeDetectorRef){}
 private visibility?:IntersectionObserver;
 ngAfterViewInit():void{
  if(typeof IntersectionObserver==='undefined'){void this.load();return;}
  this.visibility=new IntersectionObserver(entries=>{if(entries.some(entry=>entry.isIntersecting)){this.visibility?.disconnect();void this.load();}},{rootMargin:'160px'});
  this.visibility.observe(this.surface.nativeElement);
 }
 async load():Promise<void>{
  if(this.chart||this.loading||this.destroyed)return;this.loading=true;this.error='';
  try{
   const {createChart}=await import('./echarts-runtime');if(this.destroyed)return;
   this.zone.runOutsideAngular(()=>{
   this.chart=createChart(this.surface.nativeElement);
   this.chart.on('datazoom',()=>this.captureRange());
   this.chart.on('click',(item:any)=>this.openItem(item));
   this.observer=new ResizeObserver(()=>this.chart?.resize());this.observer.observe(this.surface.nativeElement);
   this.render();
   });
  }catch(error){this.disposeChart();console.error('ECharts initialization failed',error);this.error='图表加载失败';}finally{this.loading=false;if(!this.destroyed)this.zone.run(()=>this.change.markForCheck());}
 }
 ngOnChanges():void{this.render();}
 private openItem(item:any):void{
  if(item.componentType!=='series')return;
  if(this.ranks!==null){const row=this.ranks[item.dataIndex];if(row)this.zone.run(()=>this.rowOpen.emit(row));return;}
  const point=this.points[item.dataIndex];const kind:unknown=item.seriesId;
  if(point&&(kind==='alerts'||kind==='drops')&&point[kind]>0)this.zone.run(()=>this.pointOpen.emit({point,kind}));
 }
 ngDoCheck():void{if(this.seenRevision!==this.viewport.revision)this.render();}
 private palette():ChartPalette{
  const style=getComputedStyle(this.surface.nativeElement),read=(key:string,fallback:string)=>style.getPropertyValue(key).trim()||fallback;
  return {...defaultPalette,text:read('--text',defaultPalette.text),muted:read('--muted',defaultPalette.muted),line:read('--line',defaultPalette.line),surface:read('--surface',defaultPalette.surface),plot:read('--chart-plot',defaultPalette.plot),alert:read('--chart-alert',defaultPalette.alert),alertFill:read('--chart-alert-fill',defaultPalette.alertFill),drop:read('--chart-drop',defaultPalette.drop),dropFill:read('--chart-drop-fill',defaultPalette.dropFill)};
 }
 private render():void{
  if(!this.chart)return;
  this.zone.runOutsideAngular(()=>{
   const motion=!matchMedia('(prefers-reduced-motion: reduce)').matches,p=this.palette();
   const option=this.ranks!==null?rankOptions(this.ranks,this.labelKey,p,motion):trendOptions(this.points,this.viewport.range(this.points),this.viewport.extent(this.points),p,motion);
   this.seenRevision=this.viewport.revision;this.updating=true;
   try{this.chart!.setOption(option,{replaceMerge:['series'],silent:true});}finally{this.updating=false;}
  });
 }
 private captureRange():void{
  if(this.updating||this.ranks!==null||!this.chart)return;
  const zoom=(this.chart.getOption()['dataZoom'] as any[])?.[0];if(!zoom)return;
  const full=this.viewport.extent(this.points),span=full.to-full.from;
  const from=full.from+Number(zoom.start)/100*span,to=full.from+Number(zoom.end)/100*span;
  this.zone.run(()=>{this.viewport.set(this.points,from,to);this.seenRevision=this.viewport.revision;this.change.markForCheck();});
 }
 resetZoom():void{this.viewport.reset();this.render();}
 private disposeChart():void{this.observer?.disconnect();this.observer=undefined;this.chart?.dispose();this.chart=undefined;}
 ngOnDestroy():void{this.destroyed=true;this.visibility?.disconnect();this.disposeChart();}
}
