import { action, bytes, date, severity } from './core';

export interface EvidenceField { key:string; label:string; value:string; }
export interface EvidenceGroup { title:string; fields:EvidenceField[]; }
const groups: {title:string; fields:[string,string][]}[] = [
 {title:'连接流量',fields:[['flow_start','连接开始'],['flow_end','连接结束'],['flow_age','持续时间（秒）'],['bytes_toserver','客户端 → 服务端负载字节数'],['bytes_toclient','服务端 → 客户端负载字节数'],['pkts_toserver','客户端 → 服务端包数'],['pkts_toclient','服务端 → 客户端包数']]},
 {title:'事件概况',fields:[['ts','事件时间'],['type','事件类型'],['action','处置结果'],['sev','严重级别'],['level','风险等级'],['app','应用'],['proto','传输协议']]},
 {title:'通信信息',fields:[['src','源地址'],['sport','源端口'],['dst','目的地址'],['dport','目的端口'],['dir','通信方向'],['iif','采集接口'],['ip_version','IP 版本'],['vlan','VLAN 标识'],['pkt_src','数据包来源']]},
 {title:'检测信息',fields:[['sig','检测特征'],['sig_id','特征编号（SID）'],['cat','威胁分类'],['reason','阻断原因'],['ips_action','特征动作'],['ids_reason','IDS 模式原因'],['gid','生成器编号（GID）'],['rev','特征版本'],['anom','协议异常'],['anomaly_gid','异常生成器编号（GID）'],['anomaly_sid','异常特征编号（SID）']]},
 {title:'HTTP',fields:[['host','主机名'],['url','请求路径'],['method','请求方法'],['status','响应状态码'],['httpver','HTTP 版本'],['ua','用户代理'],['ct','内容类型'],['http_request_bytes','请求体字节数'],['clen','响应体字节数'],['referrer','来源页面']]},
 {title:'DNS',fields:[['dns','查询域名'],['rrtype','记录类型'],['rcode','响应代码'],['answers','解析结果'],['dns_ttl','最小应答 TTL（秒）']]},
 {title:'TLS',fields:[['sni','服务器名称（SNI）'],['tlsver','TLS 版本'],['alpn','应用层协议协商（ALPN）'],['subject','证书主体'],['issuer','证书签发者'],['cipher','密码套件'],['curve','椭圆曲线'],['validation_status','证书验证状态']]},
 {title:'SSH',fields:[['ssh_client','客户端版本'],['ssh_server','服务端版本'],['ssh_kex','密钥交换'],['ssh_hostkey','主机密钥算法'],['ssh_cipher','加密算法'],['ssh_mac','MAC 算法'],['ssh_compression','压缩算法']]},
 {title:'会话追踪',fields:[['session_event','事件'],['session_origin','观察起点'],['session_limited','记录限制'],['observed_first','首次观察'],['observed_last','最后观察'],['wire_bytes_toserver','客户端 → 服务端报文字节数'],['wire_bytes_toclient','服务端 → 客户端报文字节数']]},
 {title:'包头采样',fields:[['packet_ts','采样时间'],['packet_direction','方向'],['packet_len','报文长度'],['data_len','数据长度'],['ip_proto','IP 协议编号'],['ip_header_len','IP 报头长度'],['ip_ttl','IP TTL / 跳数限制'],['ip_tos','IP TOS / 流量类别'],['ip_id','IP 标识'],['ip_offset','分片偏移（字节）'],['ip_flags','分片标志'],['tcp_flags','TCP 标志位'],['tcp_window','TCP 窗口'],['tcp_seq','TCP 序列号'],['tcp_ack','TCP 确认号'],['tcp_options_len','TCP 选项长度']]},
 {title:'OpenAppID',fields:[['appid_service','服务'],['appid_service_id','服务编号'],['appid_client','客户端'],['appid_client_id','客户端编号'],['appid_payload','应用'],['appid_payload_id','应用编号'],['appid_misc','其他应用'],['appid_referred','关联应用']]},
 {title:'QUIC 观察',fields:[['observer','采集组件'],['coverage','证据范围'],['quic_cids','可见连接 ID'],['quic_paths','可见通信路径']]},
 {title:'文件与连接',fields:[['file','文件名'],['size','文件大小'],['magic','文件类型'],['sha256','SHA-256 校验值'],['state','连接状态'],['flow_id','流标识（Flow ID）'],['session_id','会话 ID'],['native_uid','Snort 原生 UID'],['community','连接关联标识'],['history','连接历史'],['tenant_id','租户编号'],['fuid','文件标识'],['native_source','来源协议'],['analyzers','文件分析器'],['command','FTP 命令'],['arg','命令参数'],['user','用户名'],['reply_code','FTP 响应码'],['reply_msg','FTP 响应'],['client_protocol','客户端应用协议'],['tx','事务标识'],['icmp_type','ICMP 类型'],['icmp_code','ICMP 代码']]}
];
const eventTypes:Record<string,string>={alert:'检测告警',drop:'阻断事件',flow:'网络连接',anomaly:'协议异常',fileinfo:'文件记录',session:'会话事件',stats:'引擎统计',dns:'DNS 查询',http:'HTTP 请求',tls:'TLS 会话',ssh:'SSH 会话',quic:'QUIC 会话'};
const directions:Record<string,string>={to_server:'客户端 → 服务端',toserver:'客户端 → 服务端',to_client:'服务端 → 客户端',toclient:'服务端 → 客户端'};
const levels:Record<string,string>={high:'高危',medium:'中危',low:'低危'};
const engineActions:Record<string,string>={reset:'重置连接',reject:'主动拒绝',drop:'丢弃数据包',block:'阻断',blacklist:'黑名单阻断'};
export function engineAction(value:any):string {
 const raw=String(value??'');
 return Object.hasOwn(engineActions,raw.toLowerCase())?engineActions[raw.toLowerCase()]+'（'+raw+'）':raw;
}
export function eventType(value:any):string{return eventTypes[String(value)] || String(value||'网络事件').toUpperCase();}
export function connectionSummary(record:Record<string,any>):{text:string;state:string;details:string} {
 const failed=String(record.app||'').toLowerCase()==='failed';
 const label=('连接 '+((failed?record.proto:record.app)||record.proto||'')).trim();
 let text=String(record.sig||record.summary||label).trim();
 if(!['flow','session'].includes(record.type))return {text,state:'',details:''};
 const spacing=(value:string)=>value.replace(/\s*\u00b7\s*/g,' ').trim();
 let state=String(record.state||record.flow_state||'').trim();
 let details='';
 const leading=text.match(/^连接\s+(new|established|closed|bypassed)(?:\s*\u00b7\s*(.*))?$/i);
 const embedded=text.startsWith('连接 ')?text.match(/^(.*?)\s*\u00b7\s*(new|established|closed|bypassed)(?:\s*\u00b7\s*(.*))?$/i):null;
 const bracket=text.match(/^(连接.*?)\s+\[\s*([^\]]+?)\s*\](?:\s+(.*))?$/);
 if(leading){text=label;state=state||leading[1];details=leading[2]||'';}
 else if(embedded){text=failed?label:embedded[1];state=state||embedded[2];details=embedded[3]||'';}
 else if(bracket){text=failed?label:bracket[1];state=state||bracket[2];details=bracket[3]||'';}
 else if(failed){details=text.startsWith(label+' ')?text.slice(label.length).trim():!state&&record.reason?'结束原因：'+record.reason:'';text=label;}
 if(failed&&!details.startsWith('应用协议识别失败'))details='应用协议识别失败'+(details?' '+details:'');
 return {text:spacing(text),state,details:spacing(details)};
}
export function evidenceValue(key:string,value:any):string {
 if(key==='ts'||key==='flow_start'||key==='flow_end'||key==='packet_ts')return date(value);
 if(key==='type')return eventType(value);
 if(key==='action')return action(value);
 if(key==='reason'||key==='ips_action')return engineAction(value);
 if(key==='session_event')return ({start:'发起连接',first_observed:'首次观察',state:'状态变化',application:'应用识别更新',update:'流量更新',end:'跟踪结束'} as Record<string,string>)[String(value)]||String(value);
 if(key==='session_origin')return value==='syn_observed'?'已观察到初始 SYN':'部分会话';
 if(key==='session_limited')return value==='state_limit_reached'?'已达到状态变化记录上限':String(value);
 if(key==='observed_first'||key==='observed_last')return date(Number(value));
 if(key==='wire_bytes_toserver'||key==='wire_bytes_toclient')return bytes(value);
 if(key==='sev')return severity(value);
 if(key==='level')return levels[value]||String(value);
 if(key==='dir'||key==='packet_direction')return directions[value]||String(value);
 if(key==='coverage'&&value==='passive_visible')return '被动可见 部分证据';
 if(key==='app'&&String(value).toLowerCase()==='failed')return 'FAILED（应用协议识别失败）';
 if(key==='app'||key==='proto')return String(value).toUpperCase();
 if(key==='size'||key==='http_request_bytes'||key==='clen'||key==='bytes_toserver'||key==='bytes_toclient')return bytes(value);
 if(typeof value==='object')return JSON.stringify(value,null,2);
 return String(value);
}
export function evidenceGroups(record:Record<string,any>):EvidenceGroup[] {
 const summary=['flow','session'].includes(record.type)?connectionSummary(record):null;
 const display=summary?{...record,state:summary.state}:record;
 return groups.map(group=>({title:group.title,fields:group.fields
  .filter(([key])=>!(key.startsWith('appid_')&&key.endsWith('_id')&&Number(display[key])<=0)&&display[key]!==null && display[key]!==undefined && display[key]!=='' && !(Array.isArray(display[key])&&display[key].length===0))
  .map(([key,label])=>({key,label:record.type==='quic'&&key==='alpn'?'客户端 ALPN 提议':summary&&key==='sig'?'连接摘要':summary&&key==='reason'?'连接结束原因':key==='reason'&&Object.hasOwn(engineActions,String(display[key]).toLowerCase())?'引擎处置动作':label,value:key==='sig'&&summary?summary.text+(summary.details?' '+summary.details:''):key==='reason'&&summary?String(display[key]):evidenceValue(key,display[key])}))})).filter(group=>group.fields.length>0);
}
