"""Private source definitions; public responses never contain download credentials."""
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

OFFICIAL = {
    'snort/community': ('Community', 'Snort Community text rules', 'GPLv2'),
    'snort/registered': ('Registered 免费注册', '免费注册规则集，需 Snort Oinkcode', 'Snort rules license'),
    'snort/lightspd': ('LightSPD', 'Talos LightSPD text rules', 'Snort rules license'),
}


def registered_snapshot(version='auto'):
    # Rules snapshots are published per supported engine line, not every engine patch.
    # The pinned 3.13 engine line uses the published 31300 snapshot, not 31320.
    if version in ('auto','3.13.2.0',''):return '3.13.0.0'
    return '3.12.0.0' if version=='3.12.4.0' else version


def private_write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    staged = path.with_suffix('.new')
    try:
        with staged.open('w', encoding='utf-8') as handle:
            staged.chmod(0o600)
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.flush()
            import os
            os.fsync(handle.fileno())
        staged.replace(path)
    finally:
        staged.unlink(missing_ok=True)


def custom_path(directory, name):
    if not re.fullmatch(r'custom/[a-z0-9][a-z0-9_-]{0,63}', str(name)):
        raise ValueError('自定义源标识只能包含小写字母、数字、下划线和短横线')
    return Path(directory) / (name.replace('/', '-') + '.json')


def definitions(directory):
    result = {}
    for path in sorted(Path(directory).glob('custom-*.json')):
        item = json.loads(path.read_text())
        if path != custom_path(directory, item['name']):
            raise ValueError('无效自定义源文件')
        result[item['name']] = item
    return result


def official_credentials(directory, fallback=None):
    path = Path(directory) / 'credentials.json'
    return json.loads(path.read_text()) if path.exists() else dict(fallback or {})


def public_catalog(directory, fallback=None):
    credentials = official_credentials(directory, fallback)
    rows = [dict(name=name, vendor=vendor, summary=summary, license=license_name,
                 enabled=(Path(directory)/(name.replace('/', '-')+'.yaml')).exists(),
                 custom=False, requires_code=name!='snort/community',
                 credential_configured=bool(credentials.get('oinkcode')),
                 registered_version='auto' if credentials.get('registered_version','auto')=='3.12.4.0' else credentials.get('registered_version','auto'),
                 effective_version=registered_snapshot(credentials.get('registered_version','auto')))
            for name,(vendor,summary,license_name) in OFFICIAL.items()]
    rows += [dict(name=item['name'], vendor=item['label'], summary='自定义 Snort 3 文本规则',
                  license='由规则提供方授权', custom=True, enabled=item['enabled'],
                  format=item['format'], download_host=urlsplit(item['url']).netloc,
                  credential_configured=bool(item.get('token')), requires_code=False)
             for item in definitions(directory).values()]
    return rows


def configure(directory, value, fallback=None):
    name = str(value.get('name','')).strip().lower()
    if name in OFFICIAL:
        if name == 'snort/community':
            raise ValueError('Community 不需要注册码')
        current = official_credentials(directory, fallback)
        code = value.get('oinkcode','')
        if not isinstance(code,str): raise ValueError('无效 Oinkcode')
        if code:
            if not re.fullmatch(r'[0-9a-fA-F]{40}', code.strip()):
                raise ValueError('Oinkcode 必须是 40 位十六进制字符')
            current['oinkcode'] = code.strip()
        if value.get('clear_credential') is True: current.pop('oinkcode',None)
        version = value.get('registered_version',current.get('registered_version','auto'))
        if not isinstance(version,str) or not re.fullmatch(r'(?:auto|3\.\d+\.\d+\.\d+)',version):
            raise ValueError('无效 Registered 规则快照版本')
        current['registered_version'] = version
        private_write(Path(directory)/'credentials.json',current)
    else:
        path = custom_path(directory,name)
        current = json.loads(path.read_text()) if path.exists() else dict(name=name,enabled=False)
        if value.get('delete') is True:
            path.unlink(missing_ok=True)
            return dict(ok=True)
        label = value.get('label',current.get('label',name))
        url = value.get('url') or current.get('url','')
        if not isinstance(label,str) or not 1 <= len(label.strip()) <= 100:
            raise ValueError('请输入规则源名称（最多 100 字）')
        if not isinstance(url,str) or len(url)>4096 or any(c in url for c in '\r\n'):
            raise ValueError('无效下载地址')
        parsed = urlsplit(url)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise ValueError('下载地址必须是 HTTPS，不支持内嵌用户名、密码或片段')
        format_ = value.get('format',current.get('format','rules'))
        if format_ not in ('rules','tar.gz'): raise ValueError('请选择 .rules 或 .tar.gz 格式')
        token = value.get('token', '')
        if not isinstance(token,str) or len(token)>2048 or any(c in token for c in '\r\n'):
            raise ValueError('无效下载令牌')
        current.update(label=label.strip(),url=url,format=format_)
        if token: current['token']=token
        if value.get('clear_credential') is True: current.pop('token',None)
        private_write(path,current)
    return dict(ok=True)


def set_enabled(directory, name, enabled, fallback=None):
    if type(enabled) is not bool: raise ValueError('无效启用状态')
    if name in OFFICIAL:
        path = Path(directory)/(name.replace('/','-')+'.yaml')
        if enabled:
            credentials = official_credentials(directory,fallback)
            if name!='snort/community' and not credentials.get('oinkcode'):
                raise ValueError('请先配置 Oinkcode')
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text('source: '+name+'\n')
            path.with_suffix('.yaml.disabled').unlink(missing_ok=True)
        elif path.exists(): path.replace(path.with_suffix('.yaml.disabled'))
    else:
        path = custom_path(directory,name)
        item = json.loads(path.read_text())
        item['enabled']=enabled
        private_write(path,item)
