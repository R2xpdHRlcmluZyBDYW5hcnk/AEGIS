"""Log frequencies and connection cohorts share one bounded SQL implementation."""
import time
from parallel_sql import fetch_many

APP_ORDER="(app NOT IN ('','unknown','failed')) DESC,(COALESCE(app,'')!='') DESC,(type='session') DESC,ts DESC,id DESC"


def range_bound(value):
    return value if isinstance(value,tuple) else value*1000


def resolve_bounds(push,start,end):
    if not push:return push
    return push[0],[start*1000 if value==('range','start') else end*1000 if value==('range','end') else value for value in push[1]]


def application_cohort(value,low,high):
    clause="""(session_id IN (SELECT session_id FROM
      (SELECT session_id,FIRST_VALUE(COALESCE(app,'')) OVER(PARTITION BY session_id ORDER BY """+APP_ORDER+""") name
       FROM events WHERE ts>=? AND ts<=? AND COALESCE(session_id,'')!='') WHERE LOWER(name)=?)
      OR (COALESCE(session_id,'')='' AND LOWER(COALESCE(app,''))=?))"""
    return clause,[range_bound(low),range_bound(high),value.lower(),value.lower()]


def summarize(conn, start, end, *, table='events', push=None, parallel=None, publish_base=None):
    if table not in ('events','facts'):raise ValueError('Unsupported overview source')
    volume='volume' if table=='facts' else 'COALESCE(bytes_toserver,0)+COALESCE(bytes_toclient,0)'
    origin='orig_pkts' if table=='facts' else 'pkts_toserver'
    response='resp_pkts' if table=='facts' else 'pkts_toclient'
    suffix=' AND '+' AND '.join(push[0]) if push and push[0] else ''
    args=[start*1000,end*1000,*(push[1] if push and push[0] else [])]
    selection=' FROM '+table+' WHERE ts>=? AND ts<=?'+suffix
    # Only identified records need session sorting. Each unidentified flow
    # already represents its own connection.
    cohort='''WITH selected AS MATERIALIZED (SELECT id,ts,type,COALESCE(src,'') src,COALESCE(dst,'') dst,
      COALESCE(app,'') app,COALESCE(proto,'') proto,
      COALESCE(session_id,'') session_id, CASE WHEN type='flow' THEN '''+volume+''' END volume,
      COALESCE('''+origin+''',0) orig_pkts,COALESCE('''+response+''',0) resp_pkts'''+selection+'''),
      candidates AS (SELECT src,dst,proto,
      ROW_NUMBER() OVER representative position,
      FIRST_VALUE(app) OVER (PARTITION BY session_id ORDER BY '''+APP_ORDER+''') application,
      MAX(volume) OVER complete payload,MAX(orig_pkts) OVER complete sent,
      MAX(resp_pkts) OVER complete received,MAX(ts) OVER complete latest
      FROM selected WHERE session_id!=''
      WINDOW representative AS (PARTITION BY session_id
        ORDER BY (type='flow') DESC,(type='session') DESC,ts DESC,id DESC),
        complete AS (representative ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING)),
      connections AS MATERIALIZED (
        SELECT src,dst,proto,application,payload,sent,received,latest FROM candidates WHERE position=1
        UNION ALL SELECT src,dst,proto,app,volume,orig_pkts,resp_pkts,ts
        FROM selected WHERE session_id='' AND type='flow')
      SELECT 'metrics','',COUNT(*),COALESCE(SUM(payload),0),COALESCE(SUM(sent>0 AND received>0),0),
        COALESCE(SUM((sent>0)!=(received>0)),0),MAX(latest),
        (SELECT COUNT(*) FROM (SELECT src ip FROM connections WHERE src!='' UNION SELECT dst ip FROM connections WHERE dst!=''))
      FROM connections
      UNION ALL SELECT 'application',name,n,NULL,NULL,NULL,NULL,NULL FROM
        (SELECT LOWER(application) name,COUNT(*) n FROM connections GROUP BY LOWER(application) ORDER BY n DESC,name LIMIT 8)
      UNION ALL SELECT 'protocol',name,n,NULL,NULL,NULL,NULL,NULL FROM
        (SELECT UPPER(proto) name,COUNT(*) n FROM connections GROUP BY UPPER(proto) ORDER BY n DESC,name LIMIT 8)
      UNION ALL SELECT 'connection_source',src,n,payload,NULL,NULL,latest,NULL FROM
        (SELECT src,COUNT(*) n,SUM(payload) payload,MAX(latest) latest FROM connections WHERE src!='' GROUP BY src ORDER BY n DESC,src LIMIT 8)'''
    session_column=',session_id' if publish_base is not None else ''
    logs='''WITH selected AS MATERIALIZED (SELECT ts,type,src,dst,dnsname,sni'''+session_column+selection+'''),
      source_counts AS MATERIALIZED (SELECT src,COUNT(*) n FROM selected WHERE src!='' GROUP BY src),
      destination_counts AS MATERIALIZED (SELECT dst,COUNT(*) n FROM selected WHERE dst!='' GROUP BY dst)
      SELECT 'type',type,COUNT(*),MAX(ts) FROM selected GROUP BY type
      UNION ALL SELECT 'source',src,n,NULL FROM (SELECT src,n FROM source_counts ORDER BY n DESC,src LIMIT 8)
      UNION ALL SELECT 'destination',dst,n,NULL FROM (SELECT dst,n FROM destination_counts ORDER BY n DESC,dst LIMIT 8)
      UNION ALL SELECT 'address_counts','',(SELECT COUNT(*) FROM source_counts),(SELECT COUNT(*) FROM destination_counts)
      UNION ALL SELECT 'dns',dnsname,n,NULL FROM (SELECT dnsname,COUNT(*) n FROM selected WHERE type='dns' AND dnsname!='' GROUP BY dnsname ORDER BY n DESC,dnsname LIMIT 8)
      UNION ALL SELECT 'tls',sni,n,NULL FROM (SELECT sni,COUNT(*) n FROM selected WHERE type='tls' AND sni!='' GROUP BY sni ORDER BY n DESC,sni LIMIT 8)'''
    if publish_base is None:
        connection_rows,log_rows=fetch_many(conn,[(cohort,args),(logs,args)],parallel)
    else:
        # An identified session counts once, and each unidentified flow counts once.
        logs+=''' UNION ALL SELECT 'connection_count','',COUNT(DISTINCT NULLIF(session_id,'')) +
          COUNT(CASE WHEN COALESCE(session_id,'')='' AND type='flow' THEN 1 END),NULL FROM selected'''
        log_rows=conn.execute(logs,args).fetchall()
    result=dict(range=[start,end],as_of=time.time(),records=0,flows=0,dns=0,tls=0,newest=0,
                bytes=0,bidirectional=0,one_way=0,addresses=0,source_count=0,destination_count=0,
                applications=[],protocols=[],dns_names=[],tls_names=[],sources=[],event_types=[],log_sources=[],log_destinations=[])
    for kind,name,count,extra in log_rows:
        if kind=='type':
            result['event_types'].append(dict(name=name,count=count));result['records']+=count
            result['newest']=max(result['newest'],(extra or 0)/1000)
            if name in ('dns','tls'):result[name]=count
        elif kind=='address_counts':result.update(source_count=count,destination_count=extra)
        elif kind=='connection_count':result['flows']=count
        elif kind in ('source','destination'):
            result['log_sources' if kind=='source' else 'log_destinations'].append(dict(ip=name,count=count))
        else:result['dns_names' if kind=='dns' else 'tls_names'].append(dict(name=name,count=count))
    result['event_types'].sort(key=lambda row:row['name'])
    if publish_base is not None:
        publish_base(dict(result,partial=True,bytes=None,bidirectional=None,one_way=None,addresses=None,
                          applications=[],protocols=[],sources=[]))
        connection_rows=conn.execute(cohort,args).fetchall()
    for kind,name,count,volume,bidirectional,one_way,latest,addresses in connection_rows:
        if kind=='metrics':result.update(flows=count,bytes=volume,bidirectional=bidirectional,one_way=one_way,addresses=addresses)
        elif kind=='connection_source':result['sources'].append(dict(ip=name,count=count,bytes=volume,latest=(latest or 0)/1000))
        else:result['applications' if kind=='application' else 'protocols'].append(dict(name=name or '未识别',count=count))
    return result
