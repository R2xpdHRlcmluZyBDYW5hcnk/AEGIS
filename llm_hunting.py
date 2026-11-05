"""Metadata vocabulary and observations for autonomous bounded hunting."""
from urllib.parse import urlsplit

FIELDS = ('type','src','dst','sport','dport','proto','app','action','level','sni','host','dns','url',
          'method','status','rcode','rrtype','state','bytes_toserver','bytes_toclient',
          'pkts_toserver','pkts_toclient','wire_bytes_toserver','wire_bytes_toclient','flow_age','ip_version','ip_proto','ip_ttl','ip_tos',
          'tcp_flags','tcp_window','data_len','icmp_type','icmp_code','session_event',
          'appid_service','appid_client','appid_payload','tlsver','validation_status','alpn',
          'ja3','ja3s','ja4','sha256','file','size','magic','ssh_client','ssh_server','ssh_kex',
          'ssh_cipher','command','reply_code','sig','sid','gid','reason')
NUMBERS = {'sport','dport','status','bytes_toserver','bytes_toclient','pkts_toserver',
           'pkts_toclient','wire_bytes_toserver','wire_bytes_toclient','flow_age','ip_version','ip_proto','ip_ttl','ip_tos','tcp_flags',
           'tcp_window','data_len','icmp_type','icmp_code','size','sid','gid'}
ALIASES = {'sig_id':'sid','sev':'level'}
COMMON = ('type','src','dst','sport','dport','proto','app','sni','host','dns','state',
          'bytes_toserver','bytes_toclient','pkts_toserver','pkts_toclient')


def observations(context):
    """Expose real searchable facts, without suggested queries or attack verdicts."""
    rows=[]
    for record in [context.get('anchor',{}),*context['records']]:
        row={}
        for key,value in record.items():
            field=ALIASES.get(key,key)
            if field not in FIELDS or value is None or value=='' or type(value) not in (str,int,float):continue
            if field in ('sig','sid','gid','action','level') and record.get('type') not in ('alert','drop','anomaly'):continue
            if field=='url':
                try:value=urlsplit(value).path
                except ValueError:continue
            if field=='level' and type(value) is int:value={1:'high',2:'medium',3:'low'}.get(value,'unknown')
            if field in ('sni','host','dns','sha256','ja3','ja3s','ja4'):
                if len(str(value))>253:continue
                row[field]=value
            else:row[field]=value[:100] if isinstance(value,str) else value
        if row and row not in rows:rows.append(row)
    selected=[];seen=set()
    for row in rows:
        family=row.get('type')
        if family not in seen:selected.append(row);seen.add(family)
    return selected[:6]


def vocabulary(rows):
    present={key for row in rows for key in row}
    fields=list(COMMON)+[field for field in FIELDS if field in present and field not in COMMON]
    return ','.join(field+('#' if field in NUMBERS else '') for field in fields)
