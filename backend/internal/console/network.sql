WITH selected AS MATERIALIZED (SELECT id,ts,type,COALESCE(src,'') src,COALESCE(dst,'') dst,
      COALESCE(app,'') app,COALESCE(proto,'') proto,
      COALESCE(session_id,'') session_id, CASE WHEN type='flow' THEN COALESCE(bytes_toserver,0)+COALESCE(bytes_toclient,0) END volume,
      COALESCE(pkts_toserver,0) orig_pkts,COALESCE(pkts_toclient,0) resp_pkts FROM events WHERE ts>=? AND ts<=? {{FILTER}}),
      candidates AS (SELECT session_id,src,dst,proto,volume,orig_pkts,resp_pkts,ts,
      ROW_NUMBER() OVER representative position,
      FIRST_VALUE(app) OVER (PARTITION BY session_id ORDER BY (app NOT IN ('','unknown','failed')) DESC,(COALESCE(app,'')!='') DESC,(type='session') DESC,ts DESC,id DESC) application
      FROM selected WHERE session_id!=''
      WINDOW representative AS (PARTITION BY session_id
        ORDER BY (type='flow') DESC,(type='session') DESC,ts DESC,id DESC)),
      connections AS MATERIALIZED (
        SELECT MAX(CASE WHEN position=1 THEN src END) src,
          MAX(CASE WHEN position=1 THEN dst END) dst,
          MAX(CASE WHEN position=1 THEN proto END) proto,
          MAX(application) application,MAX(volume) payload,MAX(orig_pkts) sent,
          MAX(resp_pkts) received,MAX(ts) latest FROM candidates GROUP BY session_id
        UNION ALL SELECT src,dst,proto,app,volume,orig_pkts,resp_pkts,ts
        FROM selected WHERE session_id='' AND type='flow')
      SELECT 'metrics' kind,'' name,COUNT(*) n,COALESCE(SUM(payload),0) volume,COALESCE(SUM(CASE WHEN sent>0 AND received>0 THEN 1 ELSE 0 END),0) bidirectional,
        COALESCE(SUM(CASE WHEN (sent>0)!=(received>0) THEN 1 ELSE 0 END),0) one_way,MAX(latest) latest,
        (SELECT COUNT(*) FROM (SELECT src ip FROM connections WHERE src!=''
                              UNION SELECT dst ip FROM connections WHERE dst!='')) addresses
      FROM connections
      UNION ALL SELECT 'application',name,n,NULL,NULL,NULL,NULL,NULL FROM
        (SELECT LOWER(application) name,COUNT(*) n FROM connections GROUP BY LOWER(application) ORDER BY n DESC,name LIMIT 8)
      UNION ALL SELECT 'protocol',name,n,NULL,NULL,NULL,NULL,NULL FROM
        (SELECT UPPER(proto) name,COUNT(*) n FROM connections GROUP BY UPPER(proto) ORDER BY n DESC,name LIMIT 8)
      UNION ALL SELECT 'connection_source',src,n,payload,NULL,NULL,latest,NULL FROM
        (SELECT src,COUNT(*) n,SUM(payload) payload,MAX(latest) latest FROM connections WHERE src!='' GROUP BY src ORDER BY n DESC,src LIMIT 8);
