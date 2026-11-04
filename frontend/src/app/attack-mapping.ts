import { attackCatalog } from './attack-catalog';

export interface AttackEntry { id:string; name:string; description:string; url:string; retired:boolean; }
export interface AttackMapping { tactics:AttackEntry[]; techniques:AttackEntry[]; }
const fields=['mitre_tactic_id','mitre_technique_id'] as const;

function entries(value:unknown,tactic:boolean):AttackEntry[] {
 const values=Array.isArray(value)?value:[value],ids=new Set<string>();
 for(const item of values){
  if(typeof item!=='string')continue;
  for(const token of item.split(/[\s,;|]+/)){const id=token.toUpperCase();if((tactic?/^TA[0-9]{4}$/:/^T[0-9]{4}(?:\.[0-9]{3})?$/).test(id))ids.add(id);}
 }
 return [...ids].sort().map(id=>{
  const known=attackCatalog[id];
  return {id,name:known?.[0]||'',description:known?.[1]||'',retired:known?.[2]||false,url:'https://attack.mitre.org/'+(tactic?'tactics/':'techniques/')+id.replace('.','/')+'/'};
 });
}

export function mappingFromMetadata(metadata:any):AttackMapping {
 return {tactics:entries(metadata?.[fields[0]],true),techniques:entries(metadata?.[fields[1]],false)};
}

function rawObject(value:any):any {
 if(typeof value==='string'){try{return JSON.parse(value);}catch{return null;}}
 return value&&typeof value==='object'?value:null;
}

export function mappingFromEvent(record:any,raw?:any):AttackMapping {
 const event=rawObject(raw) || rawObject(record?._raw) || record;
 return mappingFromMetadata(event?.alert?.metadata);
}

export function mappingFromRule(line:string):AttackMapping {
 const metadata:Record<string,string[]>={};
 let quoted=false,escaped=false,option='';
 const start=line.indexOf('(');
 if(start<0)return mappingFromMetadata(metadata);
 for(const char of line.slice(start+1)){
  if(char===';'&&!quoted&&!escaped){
   const match=option.match(/^\s*metadata\s*:\s*([\s\S]*)$/i);
   if(match)for(const part of match[1].split(',')){
    const item=part.trim().match(/^(mitre_(?:tactic|technique)_id)\s+(.+)$/i);
    if(item)(metadata[item[1].toLowerCase()]??=[]).push(item[2]);
   }
   option='';continue;
  }
  option+=char;
  if(escaped)escaped=false;else if(char==='\\')escaped=true;else if(char==='"')quoted=!quoted;
 }
 return mappingFromMetadata(metadata);
}
