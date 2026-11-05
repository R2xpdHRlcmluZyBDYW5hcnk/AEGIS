"""Bounded DNS evidence candidates; never merge independent connection IDs."""
from ipaddress import ip_address
import math
import re


def candidates(db, context):
    anchor=next((row for row in context['records'] if row.get('type')!='dns' and row.get('src') and row.get('dst')),None)
    if not anchor:return dict(status='not_applicable',records=[])
    try:client=str(ip_address(anchor['src']));target=str(ip_address(anchor['dst']))
    except ValueError:return dict(status='not_applicable',records=[])
    observed=[float(row['observed_first']) for row in context['records'] if row.get('observed_first')]
    first=min(observed) if observed else context['first_ts']
    if not isinstance(first,(int,float)) or not math.isfinite(first):return dict(status='not_applicable',records=[])
    rows=db.context_records("type='dns' AND src=? AND ts>=? AND ts<=?",[client,(first-300)*1000,(first+2)*1000],128)
    names={str(row.get(field,'')).strip().rstrip('.').lower() for row in context['records'] for field in ('sni','host') if row.get(field)}
    matches=[];seen=set()
    for row in rows:
        if row.get('session_id')==context.get('session_id'):continue
        name=row.get('dns','').rstrip('.')
        if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}',name):continue
        answers=set()
        for token in re.split(r'[,;\s]+',row.get('answers','')):
            try:answers.add(str(ip_address(token)))
            except ValueError:pass
        if target not in answers:continue
        age=first-row['ts'];ttl=row.get('dns_ttl')
        known=isinstance(ttl,(int,float)) and math.isfinite(ttl) and ttl>=0
        if age>max(2,ttl if known else 120):continue
        if name.lower() in seen:continue
        seen.add(name.lower())
        matches.append(dict(name=name,answer=target,client=client,ts=row['ts'],age_seconds=round(age,3),
                            ttl_seconds=ttl if known else None,name_matches=name.lower() in names,
                            session_id=row.get('session_id',''),record_id=row.get('record_id',''),relation='candidate'))
    matches.sort(key=lambda row:(not row['name_matches'],abs(row['age_seconds'])))
    return dict(status='partial' if len(rows)==128 else 'matched' if matches else 'not_found',records=matches[:2])
