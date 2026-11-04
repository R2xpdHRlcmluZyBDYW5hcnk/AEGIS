"""PulledPork3 candidates and console-specific native action policies."""
import argparse
import base64
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tarfile
import shutil
import subprocess
import tempfile
import io
import urllib.request
import time
from concurrent.futures import ThreadPoolExecutor
from collections import deque
from urllib.parse import urlsplit
from rule_sources import definitions, official_credentials, registered_snapshot
from rule_identity import parse_group,group_matches
from parallel_cpu import shared_cpu, byte_batches, worker_count
from snort_engine import configuration_lock

SOURCES = {
    'snort/community': ('Community', 'Snort Community text rules', 'GPLv2'),
    'snort/registered': ('Registered', 'Snort Registered text rules; Oinkcode required', 'Snort rules license'),
    'snort/lightspd': ('LightSPD', 'Talos LightSPD text rules; Oinkcode required', 'Snort rules license'),
}
SID = re.compile(r'\bsid\s*:\s*(\d+)')
GID = re.compile(r'\bgid\s*:\s*(\d+)')
ACTION = re.compile(r'^(alert|block|drop|reject|react|rewrite|log|pass)\s')
PULLEDPORK = Path(os.environ.get('IPS_PULLEDPORK', '/opt/pulledpork3/pulledpork.py'))


def domain_app(domain):
    return 'ipsweb-domain-' + hashlib.sha256(domain.lower().encode()).hexdigest()[:24]


def domain_detector(entries):
    lines = ["DetectorPackageInfo = {name='ips-web-bans', proto=6, client={init='DetectorInit', clean='DetectorClean', minimum_matches=1}}",
             'function DetectorInit(detector)']
    for entry in entries:
        if entry.get('type') != 'domain':
            continue
        domain = entry['value'].lower()
        if not re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]', domain):
            raise ValueError('Invalid domain detector name')
        lines.append(' local app = detector:open_createApp('+json.dumps(domain_app(domain))+')')
        lines.append(' detector:addSSLCertPattern(0, app, '+json.dumps(domain)+')')
        lines.append(' detector:addDNSHostPattern(0, app, '+json.dumps(domain)+')')
    lines.extend([' return detector', 'end', 'function DetectorClean() end'])
    return '\n'.join(lines)+'\n'


def atomic(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    candidate = path.with_suffix(path.suffix+'.new')
    try:
        candidate.write_text(text, encoding='utf-8')
        candidate.replace(path)
    finally:
        candidate.unlink(missing_ok=True)


def file_digest(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def enabled_sources(data):
    directory = Path(data) / 'update/sources'
    return {name for name in SOURCES if (directory / (name.replace('/','-')+'.yaml')).exists()} | {
        name for name,item in definitions(directory).items() if item['enabled']}


def set_source(data, name, enabled):
    if name.startswith('custom/'):
        from rule_sources import set_enabled
        return set_enabled(Path(data)/'update/sources',name,enabled)
    if name not in SOURCES:
        raise ValueError('Unknown Snort ruleset')
    path = Path(data)/'update/sources'/(name.replace('/','-')+'.yaml')
    if enabled:
        atomic(path, 'source: '+name+'\n')
        path.with_suffix('.yaml.disabled').unlink(missing_ok=True)
    elif path.exists():
        path.replace(path.with_suffix('.yaml.disabled'))


def selectors(path):
    try:
        lines = Path(path).read_text(encoding='utf-8').splitlines()
    except FileNotFoundError:
        return []
    result = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        marker = re.search(r'ips-web-selector-b64=([\w=\-]+)', line)
        if marker:
            result.append(base64.urlsafe_b64decode(marker[1]).decode())
        elif line.startswith('metadata-add '):
            continue
        else:
            result.append(line.split(' #',1)[0])
    return result


def matches(selector, line, groups=(),source=None):
    kind, _, value = selector.partition(':')
    sid = SID.search(line)
    gid = re.search(r'\bgid\s*:\s*(\d+)',line)
    generator = int(gid[1]) if gid else 1
    if selector.isdigit():
        return sid is not None and generator == 1 and sid[1] == selector
    if kind == 'sid':
        from native_rules import identity
        return sid is not None and (generator,int(sid[1])) == identity(value)
    if kind == 'group':
        return any(fnmatch.fnmatchcase(group, value) or fnmatch.fnmatchcase(group+'.rules',value) for group in groups)
    if kind == 'group-source':
        return any(group_matches(selector,group,source) for group in groups)
    if kind == 'msg':
        msg = re.search(r'\bmsg\s*:\s*"((?:\\.|[^"\\])*)"', line)
        return bool(msg and (fnmatch.fnmatchcase(msg[1],value) or msg[1].startswith(value)))
    if kind == 're':
        return re.search(value, line) is not None
    raise ValueError('Unsupported rule selector: '+selector)


def _group_tokens(lines):
    result=[]
    for line in lines:
        position=line.find('sid');match=SID.search(line,position) if position>=0 else None
        if not match:continue
        position=line.find('gid');gid=GID.search(line,position) if position>=0 else None
        generator=gid[1] if gid else '1'
        result.append(match[1] if generator=='1' else generator+':'+match[1])
    return result


def group_members(archive):
    result = {}
    with tarfile.open(archive,mode='r|*',bufsize=1<<20) as package:
        for entry in package:
            if not entry.isfile() or not entry.name.endswith('.rules') or entry.size > 128 << 20:
                continue
            group = Path(entry.name).stem
            with package.extractfile(entry) as member:text=member.read().decode('utf-8','replace')
            lines=text.replace('\\\n','').splitlines()
            tokens=(token for batch in shared_cpu().ordered(_group_tokens,byte_batches(lines,size=len)) for token in batch) if len(text)>=1<<20 else _group_tokens(lines)
            for token in tokens:
                result.setdefault(token,set()).add(group)
    return result


def apply_policy(text, directory, groups,source=None,worker_limit=None):
    directory = Path(directory)
    disabled = selectors(directory/'disable.conf')
    dropped = selectors(directory/'drop.conf')
    rejected = selectors(directory/'modify.conf')
    overrides = []
    for item in selectors(directory/'action-override.conf'):
        action, _, selector = item.partition(' ')
        if action not in ('drop','block','reject') or not selector:
            raise ValueError('Invalid action override')
        overrides.append((action,selector))
    from rule_policy import apply_policy as apply_compiled
    stats={}
    scans=any(value.partition(':')[0] in ('msg','re') for value in [*disabled,*dropped,*rejected,*(selector for _,selector in overrides)])
    output=apply_compiled(text,groups,disabled,dropped,rejected,overrides,source,
                         workers=worker_limit if scans else None,stats=stats)
    if stats:print('本地策略处理 工作进程 %d 分块 %d'%(stats['processes'],stats['chunks']),flush=True)
    return output


def read_settings(path):
    result = {}
    try:
        for line in Path(path).read_text().splitlines():
            if line.strip() and not line.lstrip().startswith('#') and '=' in line:
                key, value = line.split('=',1)
                result[key.strip().lower()] = value.strip()
    except FileNotFoundError:
        pass
    return result


def pulledpork_config(source, settings, output, work):
    values = dict(community_ruleset=source=='snort/community' or source.startswith('custom/'),
                  registered_ruleset=source=='snort/registered',
                  LightSPD_ruleset=source=='snort/lightspd',
                  snort_version='3.12.4.0', rule_mode='simple',
                  ips_policy=settings.get('ips_policy','balanced'),
                  include_disabled_rules=True,
                  ignored_files='includes.rules,snort3-deleted.rules',
                  rule_path=str(output), temp_path=str(work))
    if values['ips_policy'] not in ('balanced','connectivity','security','max-detect'):
        raise ValueError('Invalid IPS policy')
    if source in ('snort/registered','snort/lightspd'):
        secret=settings.get('oinkcode','')
        if not re.fullmatch(r'[a-fA-F0-9]{40}',secret):
            raise ValueError('This ruleset requires a valid Oinkcode')
        values['oinkcode']=secret
    if source=='snort/registered':
        version=registered_snapshot(settings.get('registered_version','auto'))
        if not re.fullmatch(r'3\.[0-9]+\.[0-9]+\.[0-9]+',version):
            raise ValueError('Invalid registered rule snapshot version')
        values['snort_version']=version
    return '\n'.join(key+' = '+str(value).lower() if isinstance(value,bool) else key+' = '+str(value)
                     for key,value in values.items())+'\n'


def update_one(data, config, source, settings, offline, program, custom=None, worker_limit=None):
    data=Path(data).resolve()
    snapshot=registered_snapshot(settings.get('registered_version','auto')) if source=='snort/registered' else ''
    print('Processing rules source: '+source+(' (snapshot '+snapshot+')' if snapshot else ''),flush=True)
    key=hashlib.sha256(source.encode()).hexdigest()[:24]
    cache=data/'update/cache';cache.mkdir(parents=True,exist_ok=True)
    archive=cache/(key+'-rules.tar.gz')
    receipt=cache/(key+'-receipt.json')
    base=cache/'derived'/(key+'.rules');metadata=base.with_suffix('.json')
    recipe=dict(source=source,policy=settings.get('ips_policy','balanced'),snapshot=snapshot,
                definition=definition_digest(custom) if custom else '',parser='console-1')
    if custom and not offline:
        download_custom(custom, archive, receipt)
    if offline or custom:
        if not archive.exists() or not receipt.exists():
            raise ValueError('规则源 '+source+' 没有本地规则，请先点击“更新规则集”')
        archive_digest=file_digest(archive)
        if archive_digest!=json.loads(receipt.read_text())['sha256']:
            raise ValueError('Cached official rules checksum differs')
        if custom and json.loads(receipt.read_text()).get('definition') != definition_digest(custom):
            raise ValueError('自定义源配置已变化，请在线更新规则')
        if offline and base.exists() and metadata.exists():
            saved=json.loads(metadata.read_text());raw=base.read_text(encoding='utf-8')
            if saved.get('recipe')==recipe and saved.get('archive')==archive_digest and saved.get('candidate')==hashlib.sha256(raw.encode()).hexdigest():
                print('本地规则策略处理: '+source,flush=True)
                return apply_policy(raw,Path(config).parent,{sid:set(groups) for sid,groups in saved['groups'].items()},source,worker_limit)
    # Disk-backed owned directory: never the router RAM /tmp and never active rules.
    with tempfile.TemporaryDirectory(prefix='pulledpork-',dir=cache) as temporary:
        work=Path(temporary);cached_input=None
        if offline or custom:
            # Preserve the upstream source identity instead of depending on
            # PulledPork's incomplete archive-content guessing for cache hashes.
            filename={'snort/community':'snort3-community-rules.tar.gz',
                      'snort/registered':'snortrules-snapshot-cached.tar.gz',
                      'snort/lightspd':'Talos_LightSPD.tar.gz'}.get(source,'snort3-community-rules.tar.gz')
            cached_input=work/filename
            if custom:
                # Feed a supported community archive to the pinned upstream parser.
                # The original archive is retained separately for group identities.
                text='\n'.join(custom_rule_files(archive).values())
                write_rules_archive(cached_input,{'snort3-community-rules/snort3-community.rules':text})
            else:
                shutil.copyfile(archive,cached_input)

        # A publishing race may temporarily pair a new digest with an old archive.
        # Retry in fresh directories and keep checksum verification mandatory.
        for attempt_index in range(3):
            attempt=work/('attempt-'+str(attempt_index));attempt.mkdir()
            candidate=attempt/'candidate.rules';private=attempt/'pulledpork.conf'
            private.write_text(pulledpork_config(source,settings,candidate,attempt),encoding='utf-8');private.chmod(0o600)
            command=[sys.executable,'-B',str(program),'-c',str(private),'-k','-q']
            if cached_input is not None: command.extend(['--file',str(cached_input)])
            with (attempt/'updater.log').open('wb') as log:
                try:
                    env=dict(os.environ,PYTHONUNBUFFERED='1',PYTHONDONTWRITEBYTECODE='1',IPS_PULLEDPORK_PROGRESS='1',IPS_PULLEDPORK_TEXT_ONLY='1')
                    if worker_limit is not None:env['IPS_PULLEDPORK_WORKERS']=str(worker_limit)
                    with ThreadPoolExecutor(max_workers=1) as runner:
                        future=runner.submit(subprocess.run,command,stdout=log,stderr=subprocess.STDOUT,timeout=900,env=env)
                        with (attempt/'updater.log').open('r',errors='replace') as progress_log:
                            while True:
                                done=future.done()
                                for message in progress_log.readlines():
                                    if message.startswith('PulledPork3 '):print(source+' '+message.rstrip(),flush=True)
                                if done:break
                                time.sleep(.2)
                        result=future.result()
                except (OSError,subprocess.TimeoutExpired):
                    raise RuntimeError('PulledPork3 failed or timed out; active rules were preserved') from None
            diagnostics=(attempt/'updater.log').read_text(errors='replace')[-2000:]
            if result.returncode==0 and candidate.is_file(): break
            if not offline and not custom and 'Official rules checksum differs' in diagnostics and attempt_index<2:
                print('上游摘要与规则归档不一致，重新下载并校验',flush=True)
                continue
            break
        if result.returncode or not candidate.is_file():
            if settings.get('oinkcode'):
                diagnostics=diagnostics.replace(settings['oinkcode'],'[redacted]')
            diagnostics=re.sub(r'https?://\S*\?\S*','[download URL]',diagnostics)
            diagnostics=re.sub(r'\x1b\[[0-9;]*m','',diagnostics)
            raise RuntimeError('PulledPork3 could not generate a rules candidate; active rules were preserved\n'+diagnostics.strip())
        downloaded=list(attempt.glob('PulledPork-*/downloaded_rulesets/*'))
        if not offline and not custom:
            downloaded=[path for path in downloaded if path.is_file() and (path.name.endswith('.tar.gz') or path.suffix=='.tgz')]
            if len(downloaded)!=1:
                raise RuntimeError('PulledPork3 did not retain exactly one official rules archive')
            original=downloaded[0]
        else:
            original=archive
        print('处理规则分组与策略: '+source,flush=True)
        groups=group_members(original)
        raw=candidate.read_text(encoding='utf-8')
        if not any(ACTION.match(line) for line in raw.splitlines()):
            raise ValueError('PulledPork3 candidate contains no active text rules')
        rendered=apply_policy(raw,Path(config).parent,groups,source,worker_limit)
        if not offline and not custom:
            pending=archive.with_suffix('.new')
            try:
                shutil.copyfile(original,pending)
                digest=hashlib.sha256(pending.read_bytes()).hexdigest()
                pending.replace(archive)
                atomic(receipt,json.dumps(dict(source=source,sha256=digest,updater='PulledPork3'),indent=2)+'\n')
            finally:
                pending.unlink(missing_ok=True)
        digest=file_digest(archive)
        atomic(base,raw)
        atomic(metadata,json.dumps(dict(recipe=recipe,archive=digest,candidate=hashlib.sha256(raw.encode()).hexdigest(),
                                       groups={sid:sorted(items) for sid,items in groups.items()}),separators=(',',':'))+'\n')
    identity_file=cache/'sources.json'
    with configuration_lock(identity_file):
        identities=json.loads(identity_file.read_text()) if identity_file.exists() else {}
        for item in identities.values(): item['enabled']=item['source'] in enabled_sources(data)
        identities[key]=dict(source=source,enabled=True)
        atomic(identity_file,json.dumps(identities,indent=2)+'\n')
    print('PulledPork3 rules candidate generated: '+source)
    return rendered


def definition_digest(item):
    return hashlib.sha256(json.dumps({k:item.get(k) for k in ('url','format','token')},sort_keys=True).encode()).hexdigest()


def write_rules_archive(path, files):
    with tarfile.open(path,'w:gz') as archive:
        for name,text in files.items():
            data=text.encode('utf-8')
            info=tarfile.TarInfo(name);info.size=len(data)
            archive.addfile(info,io.BytesIO(data))


def validate_rules_text(data):
    text=data.decode('utf-8-sig')
    for line in text.replace('\\\r\n','').replace('\\\n','').splitlines():
        value=line.strip()
        if value and not value.startswith('#') and not ACTION.match(value):
            raise ValueError('自定义源只接受 Snort 文本规则，不支持 include 或配置指令')
    return text


def custom_rule_files(path):
    files={}
    with tarfile.open(path) as archive:
        entries=archive.getmembers()
        if len(entries)>10000 or sum(e.size for e in entries)>64<<20:
            raise ValueError('自定义规则归档超出大小限制')
        from pathlib import PurePosixPath
        for entry in entries:
            name=PurePosixPath(entry.name)
            if name.is_absolute() or '..' in name.parts or not (entry.isfile() or entry.isdir()):
                raise ValueError('自定义规则归档包含不安全成员')
            if entry.isfile() and entry.name.endswith('.rules'):
                files[entry.name]=validate_rules_text(archive.extractfile(entry).read())
    if not files: raise ValueError('自定义规则归档中没有 .rules 文件')
    return files


def download_custom(item, archive, receipt):
    class HttpsRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, newurl):
            if urlsplit(newurl).scheme!='https': raise ValueError('规则源重定向必须使用 HTTPS')
            # Do not forward a bearer token to a different origin.
            redirected=super().redirect_request(request,fp,code,msg,headers,newurl)
            if urlsplit(newurl).netloc!=urlsplit(request.full_url).netloc:
                redirected.remove_header('Authorization')
            return redirected
    request=urllib.request.Request(item['url'],headers={'User-Agent':'Snort-NDR-rule-updater'})
    if item.get('token'): request.add_header('Authorization','Bearer '+item['token'])
    opener=urllib.request.build_opener(HttpsRedirect())
    data=bytearray()
    try:
        with opener.open(request,timeout=45) as response:
            while chunk:=response.read(65536):
                data.extend(chunk)
                if len(data)>64<<20: raise ValueError('规则下载超过 64 MiB 限制')
    except Exception:
        raise RuntimeError('自定义规则源下载失败，请检查地址、授权和网络；原规则已保留') from None
    pending=archive.with_suffix('.new')
    try:
        if item['format']=='rules':
            write_rules_archive(pending,{item['name'].replace('/','-')+'.rules':validate_rules_text(data)})
        else:
            pending.write_bytes(data)
            custom_rule_files(pending)
        digest=hashlib.sha256(pending.read_bytes()).hexdigest()
        pending.replace(archive)
        atomic(receipt,json.dumps(dict(source=item['name'],sha256=digest,updater='PulledPork3',definition=definition_digest(item)))+'\n')
    finally:
        pending.unlink(missing_ok=True)


def update(data='/var/lib/snort', config='/etc/snort/rule-update.conf', offline=False, program=PULLEDPORK, sources_dir=None, download_only=False):
    data=Path(data).resolve()
    source_root=Path(sources_dir) if sources_dir else data/'update/sources'
    selected={name for name in SOURCES if (source_root/(name.replace('/','-')+'.yaml')).exists()} | {name for name,item in definitions(source_root).items() if item['enabled']}
    if sources_dir is None:selected=enabled_sources(data)
    settings=read_settings(config)
    credentials=official_credentials(source_root,settings)
    settings.pop('oinkcode',None)
    settings.update(credentials)
    custom=definitions(source_root)
    lines={};owners={};comments=[]
    official_priority={'snort/community':1,'snort/registered':2,'snort/lightspd':3}
    def candidates():
        count=min(2,len(selected),worker_count())
        if count<2:
            for source in sorted(selected):
                yield source,update_one(data,config,source,settings,offline,program,custom.get(source))
            return
        from rule_policy import worker_count as policy_workers
        budget=max(1,min(worker_count()//count,policy_workers()))
        with ThreadPoolExecutor(max_workers=count,thread_name_prefix='rule-source') as pool:
            sources=iter(sorted(selected));pending=deque()
            def submit(source):
                return source,pool.submit(update_one,data,config,source,settings,offline,program,custom.get(source),budget)
            for _ in range(count):pending.append(submit(next(sources)))
            try:
                while pending:
                    source,future=pending.popleft()
                    yield source,future.result()
                    following=next(sources,None)
                    if following is not None:pending.append(submit(following))
            finally:
                for _,future in pending:future.cancel()
    for source,text in candidates():
        for line in text.splitlines():
            if not ACTION.match(line):
                comments.append(line)
                continue
            sid=SID.search(line)
            gid=re.search(r'\bgid\s*:\s*(\d+)',line)
            if not sid: raise ValueError('规则缺少 SID')
            token=(int(gid[1]) if gid else 1,int(sid[1]))
            if token in lines and lines[token]!=line:
                previous=owners[token]
                if source not in SOURCES or previous not in SOURCES:
                    raise ValueError('规则源包含冲突签名 %d:%d，请调整规则源' % token)
                revision=lambda text:int(match[1]) if (match:=re.search(r'\brev\s*:\s*(\d+)',text)) else 0
                if (revision(line),official_priority[source]) <= (revision(lines[token]),official_priority[previous]):
                    continue
            lines[token]=line
            owners[token]=source
    if not download_only:atomic(data/'rules/snort.rules','\n'.join([*comments,*lines.values()])+'\n' if selected else '# No upstream ruleset enabled\n')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',nargs='?',default='update',choices=['update','list-sources','list-enabled-sources','enable-source','disable-source'])
    parser.add_argument('source',nargs='?')
    parser.add_argument('--data-dir',default='/var/lib/snort')
    parser.add_argument('--config',default='/etc/snort/rule-update.conf')
    parser.add_argument('--offline',action='store_true')
    parser.add_argument('--sources-dir')
    parser.add_argument('--download-only',action='store_true')
    parser.add_argument('--no-reload',action='store_true')
    args=parser.parse_args()
    if args.command=='list-sources':
        for name,(vendor,summary,license_name) in SOURCES.items():
            print(f'Name: {name}\nVendor: {vendor}\nSummary: {summary}\nLicense: {license_name}')
        return 0
    if args.command=='list-enabled-sources':
        print('\n'.join('- '+name for name in sorted(enabled_sources(args.data_dir))))
        return 0
    if args.command.endswith('-source'):
        set_source(args.data_dir,args.source,args.command=='enable-source')
        return 0
    if args.offline and args.download_only:parser.error('--download-only cannot be combined with --offline')
    update(args.data_dir,args.config,args.offline,sources_dir=args.sources_dir,download_only=args.download_only)
    return 0


if __name__=='__main__':
    raise SystemExit(main())
