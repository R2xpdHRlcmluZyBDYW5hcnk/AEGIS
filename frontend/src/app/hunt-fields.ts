export interface HuntField { name:string; desc:string; example:string; values?:{value:string;label:string}[]; }
export interface HuntSuggestion extends HuntField { from:number; to:number; }

// The query parser accepts rrname as an alias for dns; older schema endpoints omit it.
export const huntAliases:Record<string,string> = {rrname:'dns'};

export function completeHuntFields(fields:HuntField[]):HuntField[] {
 const result=new Map(fields.map(field=>[field.name,field]));
 for(const [name,original] of Object.entries(huntAliases)){
  const source=result.get(original);
  if(source&&!result.has(name))result.set(name,{name,desc:'DNS 查询名称（dns 别名）',example:source.example.replace(/^[^:]+:/,name+':')});
 }
 return [...result.values()];
}

export function huntSuggestions(value:string,fields:HuntField[],caret=value.length):HuntSuggestion[] {
 const position=Math.max(0,Math.min(value.length,caret));
 let start=0,end=value.length,quoted='',escaped=false;
 for(let i=0;i<value.length;i++){
  const char=value[i];
  if(escaped){escaped=false;continue;}
  if(char==='\\'){escaped=true;continue;}
  if(quoted){if(char===quoted)quoted='';continue;}
  if(char==='"'||char==="'"){quoted=char;continue;}
  if(/[\s()]/.test(char)){
   if(i<position)start=i+1;else{end=i;break;}
  }
 }
 const spacedField=value.slice(0,start).match(/([!-]?[a-zA-Z_][a-zA-Z0-9_]*:)\s*$/);
 if(spacedField)start=spacedField.index!;
 const prefix=value.slice(start,position),colon=prefix.indexOf(':');
 const bare=prefix.replace(/^[!-]/,'');
 if(colon>=0){
  const fieldName=prefix.slice(0,colon).replace(/^[!-]/,'').toLowerCase(),field=fields.find(f=>f.name===fieldName);
  if(field?.values){
   const needle=prefix.slice(colon+1).trimStart().replace(/^["']/,'').toLowerCase(),negation=prefix.match(/^[!-]/)?.[0]||'';
   return field.values.filter(item=>item.value.toLowerCase().startsWith(needle)||(/[^\x00-\x7f]/.test(needle)&&item.label.toLowerCase().includes(needle))).map(item=>({name:field.name,example:negation+field.name+': '+(/[\s()]/.test(item.value)?JSON.stringify(item.value):item.value),desc:item.label,from:start,to:end}));
  }
  return [];
 }
 const needle=bare.toLowerCase(),negation=prefix.match(/^[!-]/)?.[0]||'';
 return fields.filter(f=>!needle||f.name.toLowerCase().startsWith(needle)||f.example.toLowerCase().startsWith(needle)||f.desc.toLowerCase().includes(needle)).map(field=>({...field,example:negation+field.name+':',from:start,to:end}));
}
