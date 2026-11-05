// AbortController owns the entire stream, including the backend's upstream inference.
export async function generateLocal(kind:string,target:any,signal:AbortSignal,action='alert',onUpdate?:(item:any)=>void):Promise<any> {
 const response=await fetch('/api/ai/generate',{method:'POST',credentials:'same-origin',signal,headers:{'Content-Type':'application/json','X-Requested-With':'ips-web'},body:JSON.stringify({kind,target,...(kind==='rule'?{action}:{})})});
 if(response.status===401){location.assign('/login');throw new Error('登录已过期');}
 if(!response.ok||!response.body)throw new Error('本地模型请求失败');
 const reader=response.body.getReader(),decoder=new TextDecoder();let buffer='';
 try{
  while(true){
   const {done,value}=await reader.read();buffer+=decoder.decode(value,{stream:!done});
   let end:number;
   while((end=buffer.indexOf('\n'))>=0){const line=buffer.slice(0,end);buffer=buffer.slice(end+1);if(!line.trim())continue;if(signal.aborted)throw new DOMException('已停止生成','AbortError');const item=JSON.parse(line);if(item.error)throw new Error(item.error);if(item.result)return item.result;onUpdate?.(item);}
   if(done)throw new Error('生成连接已中断，请重新生成');
   if(buffer.length>32768)throw new Error('模型响应超过上限');
  }
 }finally{await reader.cancel().catch(()=>{});reader.releaseLock();}
}
