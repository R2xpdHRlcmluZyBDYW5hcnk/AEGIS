import type { EChartsCoreOption } from 'echarts/core';
import type { ChartRange, TrendPoint } from './chart-viewport';

export interface ChartPalette {text:string;muted:string;line:string;surface:string;plot:string;alert:string;alertFill:string;drop:string;dropFill:string;}
export const defaultPalette:ChartPalette={text:'#e0e0e0',muted:'#b3b3b3',line:'#484848',surface:'#1e1e1e',plot:'#171717',alert:'#4c8157',alertFill:'#35533b',drop:'#ac7634',dropFill:'#724e26'};
export const escapeChartText=(value:any):string=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!));
const count=(value:any):number=>Math.max(0,Number(value)||0);
const barValues=(points:TrendPoint[],key:'alerts'|'drops')=>points.map(point=>{
 const value=count(point[key]);
 return {value:[point.t*1000,value],...(value===0?{itemStyle:{opacity:0,borderWidth:0},emphasis:{disabled:true}}:{})};
});
const clock=(value:number):string=>new Date(value).toLocaleTimeString('zh-CN',{hour:'2-digit',minute:'2-digit',hour12:false});
const date=(value:number):string=>new Date(value).toLocaleString('zh-CN',{hour12:false});
function tooltip(p:ChartPalette):any{return {className:'echarts-tooltip',confine:true,backgroundColor:p.surface,borderColor:p.line,borderWidth:1,padding:12,textStyle:{color:p.text,fontSize:12},transitionDuration:0,displayTransition:false,hideDelay:0,extraCssText:'will-change:auto;box-shadow:0 4px 16px #0006;max-width:440px;white-space:normal;overflow-wrap:anywhere;'};}
export function trendOptions(points:TrendPoint[],range:ChartRange,full:ChartRange,p:ChartPalette=defaultPalette,motion=true):EChartsCoreOption {
 return {
  animation:motion,animationDuration:250,animationDurationUpdate:180,textStyle:{fontFamily:'Segoe UI, Microsoft YaHei, sans-serif',color:p.text},
  grid:{left:48,right:20,top:32,bottom:36,show:true,backgroundColor:p.plot,borderWidth:0},
  tooltip:{...tooltip(p),trigger:'axis',axisPointer:{type:'line',animation:false,lineStyle:{color:p.muted,type:'dashed',width:1}},formatter:(items:any)=>{
   const rows=Array.isArray(items)?items:[items],stamp=Number(rows[0]?.value?.[0]);
   return `<div class="chart-tooltip-time">${escapeChartText(date(stamp))}</div>`+rows.map((r:any)=>`<div class="chart-tooltip-row"><span>${r.marker||''}${escapeChartText(r.seriesName)}</span><strong>${count(r.value?.[1]).toLocaleString()}</strong></div>`).join('');
  }},
  xAxis:{type:'time',min:full.from,max:full.to,splitNumber:5,axisLine:{lineStyle:{color:p.muted}},axisTick:{show:false},axisLabel:{color:p.muted,hideOverlap:true,formatter:clock},splitLine:{show:false}},
  yAxis:{type:'value',min:0,minInterval:1,splitNumber:3,axisLabel:{color:p.muted},splitLine:{lineStyle:{color:p.line,opacity:.5}}},
  dataZoom:[{id:'time',type:'inside',xAxisIndex:0,filterMode:'filter',rangeMode:['value','value'],startValue:range.from,endValue:range.to,minValueSpan:Math.min(full.to-full.from,2*full.step),zoomOnMouseWheel:true,moveOnMouseMove:true,moveOnMouseWheel:false,preventDefaultMouseMove:true,throttle:40}],
  series:[{id:'alerts',name:'告警',type:'bar',stack:'security',barMaxWidth:48,barMinHeight:0,itemStyle:{color:p.alertFill,borderColor:p.alert,borderWidth:1},emphasis:{focus:'none',itemStyle:{color:p.alert,borderWidth:0}},data:barValues(points,'alerts')},
   {id:'drops',name:'阻断',type:'bar',stack:'security',barMaxWidth:48,barMinHeight:0,itemStyle:{color:p.dropFill,borderColor:p.drop,borderWidth:1},emphasis:{focus:'none',itemStyle:{color:p.drop,borderWidth:0}},data:barValues(points,'drops')}]
 };
}
export function rankOptions(rows:any[],labelKey:string,p:ChartPalette=defaultPalette,motion=true):EChartsCoreOption {
 return {animation:motion,animationDuration:250,animationDurationUpdate:180,textStyle:{fontFamily:'Segoe UI, Microsoft YaHei, sans-serif',color:p.text},
  grid:{left:'46%',right:38,top:8,bottom:24},
  tooltip:{...tooltip(p),trigger:'item',formatter:(item:any)=>`${escapeChartText(rows[item.dataIndex]?.[labelKey])}<div class="chart-tooltip-row"><span>记录数</span><strong>${count(item.value).toLocaleString()}</strong></div>`},
  xAxis:{type:'value',minInterval:1,splitNumber:3,axisLabel:{color:p.muted,fontSize:11},splitLine:{lineStyle:{color:p.line,opacity:.35}}},
  yAxis:{type:'category',inverse:true,data:rows.map(r=>String(r[labelKey]??'—')),axisLine:{show:false},axisTick:{show:false},axisLabel:{color:p.text,fontSize:12,width:150,overflow:'truncate'}},
  series:[{id:'ranking',type:'bar',barMaxWidth:16,data:rows.map(r=>count(r.count)),cursor:'pointer',itemStyle:{color:p.alert,borderRadius:[0,3,3,0]},emphasis:{itemStyle:{color:'#89b97c'}},label:{show:true,position:'right',color:p.text,fontSize:12}}]
 };
}
