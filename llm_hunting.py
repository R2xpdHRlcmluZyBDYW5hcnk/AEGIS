"""Observed indicators for bounded model-authored hunting, never executable code."""
from ipaddress import ip_address
import re


def indicators(context):
    terms=[]
    def add(field,value):
        item=(field,value)
        if item not in terms:terms.append(item)
    for row in context['records']:
        for field in ('sni','host','dns'):
            name=str(row.get(field) or '').rstrip('.').lower()
            if re.fullmatch(r'[a-z0-9_][a-z0-9_.-]{1,252}',name):
                for alias in ('sni','host','dns'):add(alias,name)
        digest=str(row.get('sha256') or '').lower()
        if re.fullmatch(r'[a-f0-9]{64}',digest):add('sha256',digest)
    for row in [context.get('anchor',{}),*context['records'][:2]]:
        for field in ('dst','src'):
            try:address=str(ip_address(row[field]))
            except (KeyError,ValueError):continue
            for alias in ('src','dst'):add(alias,address)
    return terms[:12]


def scope_query(context):
    from hunt_query import quote
    terms=indicators(context)
    if not terms:raise ValueError('没有可用于 IOC 检索的已观察指标')
    return '('+' OR '.join(field+':'+quote(value) for field,value in terms)+')'
