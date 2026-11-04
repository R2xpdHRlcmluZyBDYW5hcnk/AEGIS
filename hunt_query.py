"""Bounded Lucene parsing via Luqum, adapted to the indexed event predicates."""
import json
import re


class HuntError(ValueError):
    pass


def quote(value):
    return json.dumps(str(value),ensure_ascii=False)


def _value(node):
    """Keep Lucene escapes and quoted wildcards literal in fnmatch predicates."""
    phrase=type(node).__name__=='Phrase'
    raw=node.value[1:-1] if phrase else node.value
    characters=[];index=0
    while index<len(raw):
        escaped=raw[index]=='\\'
        if escaped:
            index+=1
            if index==len(raw):raise HuntError('搜索值末尾缺少转义字符')
        characters.append((raw[index],phrase or escaped));index+=1
    pattern=any(char in '*?' for char,literal in characters)
    return ''.join('[[]' if pattern and char=='[' else
                   ('['+char+']' if pattern and literal and char in '*?' else char)
                   for char,literal in characters)


def parse_query(text, fields, numeric):
    if not isinstance(text,str) or not text.strip():raise HuntError('搜索条件不能为空')
    if len(text)>8192 or any(ord(char)<32 and char not in '\t\r\n' for char in text):
        raise HuntError('搜索条件过长或含无效控制字符')
    from python_dependencies import activate
    activate()
    from luqum import tree
    from luqum.thread import parse
    from luqum.exceptions import ParseError
    try:root=parse(text)
    except (ParseError,ValueError,RecursionError) as exc:
        position=re.search(r'position\s+(\d+)',str(exc))
        location='，位置 '+str(int(position.group(1))+1) if position else ''
        raise HuntError('Lucene 搜索语法无效'+location+'；IPv6、URL 和含空格的值请使用双引号') from None
    visited=0

    def atom(node):
        if isinstance(node,tree.Prohibit):return '-'+atom(node.a)
        if not isinstance(node,(tree.Word,tree.Phrase)):raise HuntError('范围边界必须是数值')
        return _value(node)

    def comparison(field,operator,value):
        if field not in numeric:raise HuntError('字段 '+field+' 不支持数值范围')
        if not re.fullmatch(r'[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?',value):
            raise HuntError('字段 '+field+' 的范围边界必须是数值')
        return ('cmp',field,operator+value)

    def convert(node,field=None,depth=0):
        nonlocal visited
        visited+=1
        if visited>1024 or depth>20:raise HuntError('搜索条件过于复杂')
        if isinstance(node,(tree.AndOperation,tree.OrOperation,tree.UnknownOperation)):
            operator='or' if isinstance(node,tree.OrOperation) else 'and'
            # Normalize long associative lists without recursively walking a
            # left-deep upstream tree. Balanced predicates also bound later
            # SQL and memory evaluation stack usage.
            pending=list(reversed(node.children));leaves=[]
            while pending:
                child=pending.pop()
                if isinstance(child,tree.Word) and child.value.upper() in ('AND','OR','NOT') and child.value!=child.value.upper():
                    raise HuntError('布尔连接词必须大写：AND / OR / NOT；搜索这些文字时请使用双引号')
                same=isinstance(child,tree.OrOperation) if operator=='or' else isinstance(child,(tree.AndOperation,tree.UnknownOperation))
                if same:
                    visited+=1
                    if visited>1024:raise HuntError('搜索条件过于复杂')
                    pending.extend(reversed(child.children))
                else:leaves.append(child)
            children=[convert(child,field,depth+1) for child in leaves]
            while len(children)>1:
                children=[(operator,children[i],children[i+1]) if i+1<len(children) else children[i]
                          for i in range(0,len(children),2)]
            return children[0]
        if isinstance(node,(tree.Not,tree.Prohibit)):
            return ('not',convert(node.a,field,depth+1))
        if isinstance(node,(tree.Group,tree.FieldGroup)):
            return convert(node.expr,field,depth+1)
        if isinstance(node,tree.SearchField):
            name=node.name.lower()
            if name not in fields:raise HuntError('未知字段：'+name)
            if field is not None:raise HuntError('字段分组内不能再指定其他字段')
            return convert(node.expr,fields[name],depth+1)
        if isinstance(node,tree.Range):
            if field is None:raise HuntError('范围条件需要指定字段')
            low,high=atom(node.low),atom(node.high);parts=[]
            if low!='*':parts.append(comparison(field,'>=' if node.include_low else '>',low))
            if high!='*':parts.append(comparison(field,'<=' if node.include_high else '<',high))
            return ('and',*parts) if len(parts)==2 else parts[0] if parts else ('cmp',field,'*')
        if isinstance(node,(tree.From,tree.To)):
            if field is None:raise HuntError('比较条件需要指定字段')
            operator=('>' if isinstance(node,tree.From) else '<')+('=' if node.include else '')
            return comparison(field,operator,atom(node.a))
        if isinstance(node,(tree.Word,tree.Phrase)):
            value=_value(node)
            if not value:raise HuntError('搜索值不能为空')
            if value in ('&&','||','!'):raise HuntError('逻辑条件请使用 AND、OR、NOT')
            if field in numeric and value!='*' and not re.fullmatch(r'[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?',value):
                raise HuntError('数值字段 '+field+' 需要数值、比较条件或范围')
            return ('cmp',field,value) if field else ('bare',value)
        raise HuntError('不支持 '+type(node).__name__+'；支持字段过滤、AND / OR / NOT、分组、通配符和数值范围')

    return convert(root)
