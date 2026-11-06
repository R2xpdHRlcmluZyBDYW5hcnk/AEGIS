import { Injectable, NgZone, signal, afterEveryRender } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom, timeout, fromEvent, takeUntil } from 'rxjs';

export type Page = 'overview'|'alerts'|'hunt'|'drops'|'rules'|'system';
export const pages: {id:Page; title:string}[] = [
  {id:'overview',title:'安全概览'},
  {id:'alerts',title:'安全事件'},
  {id:'hunt',title:'威胁狩猎'},
  {id:'drops',title:'阻断日志'},
  {id:'rules',title:'规则管理'},
  {id:'system',title:'系统状态'}
];
@Injectable({providedIn:'root'})
export class ConsoleState {
  readonly page = signal<Page>('overview');
  readonly views=new Map<string,any>();
  readonly investigation=signal(0);
  private scrollPositions=new Map<Page,number>();
  private pendingScroll:{page:Page;top:number;ready:boolean;initialized:boolean}|undefined;
  constructor(){afterEveryRender(()=>{
   const pending=this.pendingScroll;if(!pending)return;
   if(this.page()!==pending.page){this.pendingScroll=undefined;return;}
   const main=document.querySelector('main');
   if(!main)return;
   if(!pending.ready){if(!pending.initialized){main.scrollTop=0;pending.initialized=true;}return;}
   this.pendingScroll=undefined;
   if(getComputedStyle(main).overflowY==='auto')main.scrollTop=Math.min(pending.top,Math.max(0,main.scrollHeight-main.clientHeight));
   else window.scrollTo({top:pending.top});
  });}
  readonly huntFlow = signal<string|null>(null);
  readonly huntCommunity = signal<string|null>(null);
  readonly huntTuple = signal<string|null>(null);
  readonly huntQuery = signal('');
  readonly huntTime = signal<{from:string;to:string}|null>(null);
  readonly huntRange = signal<{choice:string;from:string;to:string}|null>(null);
  readonly notice = signal('');
  readonly confirmation = signal<{title:string;message:string;resolve:(ok:boolean)=>void}|null>(null);
  private timer: ReturnType<typeof setTimeout>|undefined;
  navigate(page:Page):void {if(this.page()!==page){const main=document.querySelector('main');this.scrollPositions.set(this.page(),main?main.scrollTop:window.scrollY);this.page.set(page);this.pendingScroll={page,top:this.scrollPositions.get(page)||0,ready:false,initialized:false};}if(location.hash!=='#'+page)history.pushState(null,'','#'+page);document.title=pages.find(p=>p.id===page)?.title+' AEGIS';}
  viewReady(page:Page):void{if(this.pendingScroll?.page===page)this.pendingScroll.ready=true;}
  cancelScrollRestore():void{this.pendingScroll=undefined;}
  scrollKey(event:KeyboardEvent):void{if(['ArrowUp','ArrowDown','PageUp','PageDown','Home','End',' '].includes(event.key))this.cancelScrollRestore();}
  investigate(query:string,ts?:number,range?:{choice:string;from:string;to:string}):void {
   const flow=range?null:query.match(/^flow:\s*([0-9]+)$/)?.[1]||null;
   let community:string|null=null;
   const selected=!range?query.match(/^community(?:_id)?:\s*(.+)$/)?.[1]:undefined;
   if(selected){try{const value=selected.startsWith('"')?JSON.parse(selected):selected;if(typeof value==='string')community=value;}catch{}}
   const tuple=!range?query.match(/^tuple_hash:\s*([0-9a-f]{64})$/)?.[1]||null:null;
   this.huntTuple.set(tuple);this.huntFlow.set(flow);this.huntCommunity.set(community);this.huntRange.set(range?{...range}:null);this.huntQuery.set(query);
   this.huntTime.set(ts && !flow && !community && !tuple && !range ? {from:localDate(new Date(ts*1000-900000)),to:localDate(new Date(ts*1000+900000))}:null);
   this.investigation.update(n=>n+1);this.navigate('hunt');
  }
  toast(text:string):void {this.notice.set(text);clearTimeout(this.timer);this.timer=setTimeout(()=>this.notice.set(''),6000);}
  confirm(title:string,message:string):Promise<boolean> {return new Promise(resolve=>this.confirmation.set({title,message,resolve}));}
  answer(ok:boolean):void {this.confirmation()?.resolve(ok);this.confirmation.set(null);}
}
@Injectable({providedIn:'root'})
export class Api {
  constructor(private http:HttpClient, readonly zone:NgZone) {}
  async request(path:string,method='GET',body?:unknown,signal?:AbortSignal):Promise<any> {
    try {
      if(signal?.aborted)throw new DOMException('请求已取消','AbortError');
      const request=this.http.request(method,path,{body,headers:{'X-Requested-With':'ips-web'},withCredentials:true}).pipe(timeout(120000));
      const value:any=await firstValueFrom(signal?request.pipe(takeUntil(fromEvent(signal,'abort'))):request);
      if (value?.error && value.error !== 'already running') throw new Error(value.error);
      return value;
    } catch(error:any) {
      if(signal?.aborted)throw new DOMException('请求已取消','AbortError');
      if(error.status===401) location.assign('/login');
      throw new Error(error.error?.error || error.message || '请求失败');
    }
  }
  get(path:string,params:Record<string,any>={},signal?:AbortSignal):Promise<any> {const query=new URLSearchParams();Object.entries(params).forEach(([k,v])=>{if(v!==undefined && v!==null && v!=='')query.set(k,String(v));});return this.request(path+(query.size?'?'+query:''),'GET',undefined,signal);}
  async post(path:string,body:any={}):Promise<any> {const r=await this.request(path,'POST',body);if(r.ok===false)throw new Error(r.message||r.output||r.error||'操作未完成');return r;}
  async delete(path:string):Promise<any> {const r=await this.request(path,'DELETE');if(r.ok===false)throw new Error(r.message||'删除失败');return r;}
  async logout():Promise<void> {try{await firstValueFrom(this.http.post('/logout',{}, {responseType:'text',headers:{'X-Requested-With':'ips-web'}}));}finally{location.assign('/login');}}
}
// Each replacement closes the old stream and ignores in-flight replies from older queries.
export class LiveQuery {
  private revision=0; private request?:AbortController; private source?:EventSource; private fallback?:ReturnType<typeof setInterval>;private initial?:ReturnType<typeof setTimeout>;private interruption?:ReturnType<typeof setTimeout>;
  constructor(private api:Api,private receive:(data:any)=>void,private error:(message:string)=>void,private notice:(message:string)=>void=error){}
  start(path:string,params:Record<string,any>,topic?:string):void {
    this.stop();const revision=this.revision;
    const accept=(data:any)=>this.api.zone.run(()=>{
      this.receive(data);
      const read=data.read_state;
      if(revision!==this.revision||read?.status!=='stale')return;
      const message='更新延迟，显示上次结果'+(read.as_of?'（'+date(read.as_of)+'）':'');
      if(read.error)this.error(message+'：'+read.error);
      else this.notice(message);
    });
    const interrupted=(message:string)=>{if(this.interruption)return;this.interruption=setTimeout(()=>{this.interruption=undefined;if(revision===this.revision&&this.source?.readyState!==EventSource.OPEN)this.api.zone.run(()=>this.error(message));},6000);};
    const fetch=()=>{if(this.request)return;const request=this.request=new AbortController();return this.api.get(path,params,request.signal).then(data=>{if(revision===this.revision&&!request.signal.aborted){clearTimeout(this.interruption);this.interruption=undefined;accept(data);}}).catch(e=>{if(revision===this.revision&&!request.signal.aborted){if(topic)interrupted(e.message);else this.api.zone.run(()=>this.error(e.message));}}).finally(()=>{if(this.request===request)this.request=undefined;});};
    if(topic){
      const query=new URLSearchParams({...params,topic} as Record<string,string>);
      this.source=new EventSource('/api/stream?'+query);
      this.initial=setTimeout(()=>{if(revision===this.revision)void fetch();},2000);
      this.source.onmessage=e=>{if(revision!==this.revision)return;clearTimeout(this.initial);clearTimeout(this.interruption);this.interruption=undefined;try{const data=JSON.parse(e.data);if(data.status===401){location.assign('/login');return;}if(data.error){this.api.zone.run(()=>this.error(data.error));return;}this.request?.abort();this.request=undefined;accept(data);}catch{this.api.zone.run(()=>this.error('实时数据格式错误'));}};
      this.source.onerror=()=>{if(revision===this.revision){interrupted('实时连接中断，正在重连；保留最近数据');void fetch();}};
      this.fallback=setInterval(()=>{if(!document.hidden && this.source?.readyState!==EventSource.OPEN)void fetch();},5000);
    }else void fetch();
  }
  stop():void {this.revision++;this.request?.abort();this.request=undefined;this.source?.close();this.source=undefined;clearInterval(this.fallback);clearTimeout(this.initial);clearTimeout(this.interruption);this.interruption=undefined;}
}
export function localDate(d:Date):string {const p=(n:number)=>String(n).padStart(2,'0');return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;}
export function timeRange(choice:string,from:string,to:string):Record<string,string> {
  if(choice==='all')return {all:'1'};
  if(choice==='custom'){const a=new Date(from),b=new Date(to);if(!from||!to||!Number.isFinite(+a)||!Number.isFinite(+b)||+a>+b)throw new Error('请输入有效的起止时间，开始时间不得晚于结束时间');return {from:String(+a/1000),to:String(+b/1000)};}
  if(choice==='today'||choice==='yesterday'){const d=new Date();d.setHours(0,0,0,0);if(choice==='today')return {from:String(+d/1000)};const end=+d;d.setDate(d.getDate()-1);return {from:String(+d/1000),to:String(end/1000)};}
  return {window:choice};
}
export function date(value:any):string {return value ? new Date(Number(value)*1000).toLocaleString('zh-CN',{hour12:false}) : '—';}
export function bytes(value:any):string {if(value==null)return '—';const n=Number(value);const i=n>0?Math.min(4,Math.floor(Math.log(n)/Math.log(1024))):0;return (n/1024**i).toFixed(i?1:0)+' '+['B','KiB','MiB','GiB','TiB'][i];}
export function severity(value:any):string {return Number(value)===1?'高危':Number(value)===2?'中危':Number(value)===3?'低危':'未评级';}
export function action(value:any):string {return ['blocked','block','drop','reject'].includes(value)?'已阻断':value==='allowed'||value==='pass'?'已放行':value||'—';}
export function canonical(value:string):string {const [kind,...rest]=value.split(':');const code=rest.join(':').trim();if(!rest.length && /^\d+$/.test(kind))return 'sid:'+Number(kind);return kind==='sid'?'sid:'+code.split(':').map(n=>/^\d+$/.test(n)?String(Number(n)):n).join(':'):kind==='group'?'group:'+code.replace(/\.rules$/,''):value.trim();}
export function groupSelector(name:string,source?:string):string{return source===undefined?'group:'+name:'group-source:'+encodeURIComponent(source)+':'+encodeURIComponent(name);}
export function groupTarget(value:string):string{if(!value.startsWith('group-source:'))return value.split(':').slice(1).join(':');const [,source,...name]=value.split(':');try{return decodeURIComponent(name.join(':'))+' '+decodeURIComponent(source);}catch{return value;}}
