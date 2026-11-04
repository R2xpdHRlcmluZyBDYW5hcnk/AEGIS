export interface TrendPoint {t:number;alerts:number;drops:number;}
export interface ChartRange {from:number;to:number;step:number;}

// Only the visible time range is shared; ECharts handles zoom and pan gestures.
export class ChartViewport {
 private selection?:ChartRange;
 revision=0;
 get zoomed():boolean{return !!this.selection;}
 reset():void{this.selection=undefined;this.revision++;}
 extent(points:TrendPoint[]):ChartRange {
  const step=points.length>1?Math.max(1,(points[1].t-points[0].t)*1000):60000;
  const first=(points[0]?.t||0)*1000,last=(points.at(-1)?.t||0)*1000;
  return {from:first-step/2,to:last+step/2,step};
 }
 range(points:TrendPoint[]):ChartRange {
  const full=this.extent(points),selected=this.selection;
  if(!selected)return full;
  if(!points.length||selected.step!==full.step||selected.from>=full.to||selected.to<=full.from){this.reset();return full;}
  const span=Math.min(selected.to-selected.from,full.to-full.from);
  const from=Math.max(full.from,Math.min(full.to-span,selected.from));
  return {from,to:from+span,step:full.step};
 }
 set(points:TrendPoint[],from:number,to:number):void {
  if(!points.length||!Number.isFinite(from)||!Number.isFinite(to)||from>=to)return;
  const full=this.extent(points),span=Math.min(to-from,full.to-full.from);
  from=Math.max(full.from,Math.min(full.to-span,from));to=from+span;
  if(from<=full.from+1&&to>=full.to-1){if(this.selection)this.reset();return;}
  if(this.selection?.from===from&&this.selection?.to===to)return;
  this.selection={from,to,step:full.step};this.revision++;
 }
}
