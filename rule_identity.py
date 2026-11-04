"""Stable source-qualified group selectors shared by policy and presentation."""
import fnmatch
from functools import lru_cache
from pathlib import Path
from urllib.parse import quote,unquote


def group_selector(name,source=None):
    name=str(name).removesuffix('.rules')
    if not name or any(c in name for c in '\r\n\0'):raise ValueError('无效规则分组')
    if source is None:return 'group:'+name
    source=str(source)
    if not source or any(c in source for c in '\r\n\0'):raise ValueError('无效规则来源')
    return 'group-source:'+quote(source,safe='')+':'+quote(name,safe='')


def parse_group(value):
    return _parse_group(str(value))


@lru_cache(maxsize=4096)
def _parse_group(value):
    kind,separator,code=value.partition(':')
    if kind=='group-source' and separator:
        source,separator,name=code.partition(':')
        if not separator:raise ValueError('规则分组缺少来源或名称')
        source,name=unquote(source,errors='strict'),unquote(name,errors='strict')
        group_selector(name,source)
        return source,name.removesuffix('.rules')
    if kind=='group' and separator:
        group_selector(code)
        return None,code.removesuffix('.rules')
    if not separator:
        group_selector(value)
        return None,str(value).removesuffix('.rules')
    raise ValueError('无效规则分组选择器')


def group_matches(value,name,source):
    selected,pattern=parse_group(value)
    return (selected is None or selected==source) and (fnmatch.fnmatchcase(name,pattern) or fnmatch.fnmatchcase(name+'.rules',pattern))


def group_policy_path(threshold):
    return Path(threshold).with_name('group-suppressions.json')
