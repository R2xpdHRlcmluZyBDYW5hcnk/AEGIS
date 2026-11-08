WITH selected AS MATERIALIZED (SELECT ts,type,src,dst,dnsname,sni FROM events WHERE ts>=? AND ts<=? {{FILTER}}),
      source_counts AS MATERIALIZED (SELECT src,COUNT(*) n FROM selected WHERE src!='' GROUP BY src),
      destination_counts AS MATERIALIZED (SELECT dst,COUNT(*) n FROM selected WHERE dst!='' GROUP BY dst)
      SELECT 'type' kind,type name,COUNT(*) n,MAX(ts) extra FROM selected GROUP BY type
      UNION ALL SELECT 'source',src,n,NULL FROM (SELECT src,n FROM source_counts ORDER BY n DESC,src LIMIT 8)
      UNION ALL SELECT 'destination',dst,n,NULL FROM (SELECT dst,n FROM destination_counts ORDER BY n DESC,dst LIMIT 8)
      UNION ALL SELECT 'address_counts','',(SELECT COUNT(*) FROM source_counts),(SELECT COUNT(*) FROM destination_counts)
      UNION ALL SELECT 'dns',dnsname,n,NULL FROM (SELECT dnsname,COUNT(*) n FROM selected WHERE type='dns' AND dnsname!='' GROUP BY dnsname ORDER BY n DESC,dnsname LIMIT 8)
      UNION ALL SELECT 'tls',sni,n,NULL FROM (SELECT sni,COUNT(*) n FROM selected WHERE type='tls' AND sni!='' GROUP BY sni ORDER BY n DESC,sni LIMIT 8);
