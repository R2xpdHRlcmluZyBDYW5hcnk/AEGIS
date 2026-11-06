"""Snort 3 native event normalization and bounded local control channel."""
from datetime import datetime, timezone
from contextlib import contextmanager
import errno
import hashlib
from ipaddress import ip_address
import json
import math
from pathlib import Path
import re
import socket
import time
import threading
import os
from parallel_cpu import shared_cpu, byte_batches
from log_storage import log_paths

PREFIX = os.environ.get('SNORT_ENGINE_PREFIX','/opt/ips-snort3/3.12.4.0')
BINARY = PREFIX + '/bin/snort'
CONFIG = '/etc/snort/snort.lua'
SOCKET = '/run/snort/control.sock'
RULES = '/var/lib/snort/rules/snort.rules'
EVENTS = str(log_paths()[1])
_CONFIG_THREAD_LOCK = threading.RLock()


@contextmanager
def configuration_lock(config=CONFIG, *, blocking=True):
    """Serialize rules, scope refresh and deployment across independent processes."""
    if not _CONFIG_THREAD_LOCK.acquire(blocking=blocking):
        raise BlockingIOError(errno.EAGAIN, 'Snort configuration is busy')
    try:
        try: import fcntl
        except ImportError:
            yield
            return
        with Path(config).with_name('.configuration.lock').open('a') as handle:
            fcntl.flock(handle,fcntl.LOCK_EX if blocking else fcntl.LOCK_EX|fcntl.LOCK_NB)
            try: yield
            finally: fcntl.flock(handle,fcntl.LOCK_UN)
    finally:
        _CONFIG_THREAD_LOCK.release()

NATIVE_FIELDS = {
    'session_id': 'session_id',
    'uid': 'native_uid', 'history': 'history', 'tenant_id': 'tenant_id',
    'cipher': 'cipher', 'curve': 'curve', 'validation_status': 'validation_status',
    'client_protocol': 'client_protocol', 'command': 'command', 'arg': 'arg',
    'user': 'user', 'reply_code': 'reply_code', 'reply_msg': 'reply_msg',
    'fuid': 'fuid', 'source': 'native_source', 'analyzers': 'analyzers',
    'timedout': 'file_timeout', 'extracted_cutoff': 'extracted_cutoff',
    'ips_action': 'ips_action', 'ids_reason': 'ids_reason',
    'dns_ttl': 'dns_ttl',
    'client.version':'ssh_client','server.version':'ssh_server','kex_alg':'ssh_kex','host_key_alg':'ssh_hostkey',
    'cipher_alg':'ssh_cipher','mac_alg':'ssh_mac','compression_alg':'ssh_compression',
    **{name:name for name in ('packet_ts','packet_len','data_len','packet_direction','ip_ttl','ip_tos','ip_id','ip_offset','ip_flags','ip_proto','ip_header_len',
                            'tcp_flags','tcp_window','tcp_seq','tcp_ack','tcp_options_len')},
    **{name:name for name in ('session_event','session_origin','session_limited','observed_first','observed_last','wire_bytes_toserver','wire_bytes_toclient',
        'appid_service','appid_client','appid_payload','appid_misc','appid_referred',
        'appid_service_id','appid_client_id','appid_payload_id','appid_misc_id','appid_referred_id')},
}
PACKET_NUMBER_FIELDS=('packet_ts','packet_len','data_len','ip_ttl','ip_tos','ip_id','ip_offset','ip_flags','ip_proto','ip_header_len',
                      'tcp_flags','tcp_window','tcp_seq','tcp_ack','tcp_options_len')
EVENT_FIELDS={**NATIVE_FIELDS,**__import__('quic_observer').OBSERVER_FIELDS}


def record_kind(data):
    """Discriminators are required by the shipped extractor configuration."""
    if 'sid' in data:
        return 'notice' if 'rev' in data else 'weird'
    for field, kind in (('orig_pkts', 'conn'), ('trans_depth', 'http'),
                        ('trans_id', 'dns'), ('fuid', 'file'),
                        ('client_initial_dcid', 'quic'), ('reply_code', 'ftp'),
                        ('module_identifier', 'ssl'), ('direction', 'ssh')):
        if field in data:
            return kind
    return None


def timestamp(value):
    try:
        number = float(value)
        if not math.isfinite(number) or number <= 0:
            return ''
        return datetime.fromtimestamp(number, timezone.utc).isoformat(timespec='microseconds')
    except (ValueError, TypeError, OverflowError, OSError):
        return ''


_RULE_CACHE = (None, {})


def _metadata_lines(argument):
    lines,classifications=argument
    result={}
    for line in lines:
        if not re.match(r'^(alert|block|drop|reject|pass|log|react|rewrite)\s', line):
            continue
        sid = re.search(r'\bsid\s*:\s*(\d+)', line)
        if not sid:
            continue
        gid = re.search(r'\bgid\s*:\s*(\d+)', line)
        classtype = re.search(r'\bclasstype\s*:\s*([^;\s]+)', line)
        priority = re.search(r'\bpriority\s*:\s*(\d+)', line)
        metadata = {}
        for field in ('mitre_tactic_id', 'mitre_technique_id', 'mitre_tactic_name', 'mitre_technique_name'):
            values = re.findall(r'\b' + field + r'\s+([^,;]+)', line)
            if values:
                metadata[field] = values
        category = classtype[1] if classtype else ''
        result[(int(gid[1]) if gid else 1, int(sid[1]))] = dict(
            category=category, severity=int(priority[1]) if priority else classifications.get(category, 0),
            metadata=metadata)
    return result


_RULE_METADATA_LOCK=threading.Lock()


def rule_metadata(path=RULES):
    with _RULE_METADATA_LOCK:
        return _load_rule_metadata(path)


def _load_rule_metadata(path):
    """Read only the active, local text rules; never fetch while ingesting."""
    global _RULE_CACHE
    paths = [Path(path)] if path != RULES else [Path(RULES).parent/name for name in
            ('snort.rules','local.rules','ips-web-hunting.rules','ips-web-bans.rules')]
    signature=[]
    for current in paths:
        try:
            stat=current.stat();signature.append((str(current),stat.st_ino,stat.st_mtime_ns,stat.st_size))
        except OSError: pass
    if _RULE_CACHE[0] == signature:
        return _RULE_CACHE[1]
    classifications = {}
    try:
        defaults = Path(PREFIX + '/etc/snort/snort_defaults.lua').read_text()
        for item in re.findall(r'\{([^{}]*name\s*=\s*[^{}]*)\}', defaults):
            name = re.search(r'name\s*=\s*[\'"]([^\'"]+)', item)
            priority = re.search(r'priority\s*=\s*(\d+)', item)
            if name and priority:
                classifications[name[1]] = int(priority[1])
    except OSError:
        pass
    result = {}
    for current in paths:
        try: lines=current.read_text(encoding='utf-8').splitlines()
        except OSError: continue
        if sum(map(len,lines))>=1<<20 and os.environ.get('IPS_CPU_CHILD')!='1':
            jobs=((batch,classifications) for batch in byte_batches(lines,size=len))
            for rows in shared_cpu().ordered(_metadata_lines,jobs):result.update(rows)
        else:result.update(_metadata_lines((lines,classifications)))
    _RULE_CACHE = (signature, result)
    return result


def session_observation(envelope):
    """Validate native lifecycle data without guessing protocol or membership."""
    data=envelope.get('data')
    if not isinstance(data,dict):return {}
    identity=data.get('session_id','');event=data.get('event')
    if not isinstance(identity,str) or not re.fullmatch(r'[0-9a-f]{32}:[0-9a-f]{16}',identity):return {}
    if identity.endswith(':0000000000000000') or event not in ('start','first_observed','state','application','update','end'):return {}
    try:
        source,target=str(ip_address(data['src'])),str(ip_address(data['dst']))
        if type(data['sport']) is not int or type(data['dport']) is not int:return {}
        if not all(0<=data[key]<=65535 for key in ('sport','dport')):return {}
        proto=data['proto']
        if proto not in ('TCP','UDP','ICMP','IP'):return {}
        first,last,ts=(float(data[key]) for key in ('first_observed','last_observed','ts'))
        if not all(math.isfinite(value) and value>0 for value in (first,last,ts)) or last<first:return {}
        native=dict(session_id=identity,session_event=event,observed_first=first,observed_last=last)
        if type(data.get('initial_syn_observed')) is not bool or type(data.get('state_limit_reached')) is not bool:return {}
        native.update(session_origin='syn_observed' if data['initial_syn_observed'] else 'partial',
                      session_limited='state_limit_reached' if data['state_limit_reached'] else '')
        for field in ('service','client','payload','misc','referred'):
            name=data.get('appid_'+field,'');number=data.get('appid_'+field+'_id',0)
            if not isinstance(name,str) or len(name.encode('utf-8'))>1012 or type(number) is not int or not -1<=number<=2147483647:return {}
            native['appid_'+field]=name;native['appid_'+field+'_id']=number
        for key in ('orig_pkts','resp_pkts','orig_wire_bytes','resp_wire_bytes'):
            if type(data.get(key)) is not int or not 0<=data[key]<(1<<63):return {}
        native.update(wire_bytes_toserver=data['orig_wire_bytes'],wire_bytes_toclient=data['resp_wire_bytes'])
        limits=dict(icmp_type=255,icmp_code=255,packet_len=0xffffffff,data_len=65535,ip_ttl=255,ip_tos=65535,ip_id=0xffffffff,ip_offset=65535,
                    ip_flags=7,ip_proto=255,ip_header_len=255,tcp_flags=255,tcp_window=65535,tcp_seq=0xffffffff,tcp_ack=0xffffffff,tcp_options_len=255)
        for key,maximum in limits.items():
            if key in data:
                if type(data[key]) is not int or not 0<=data[key]<=maximum:return {}
                native[key]=data[key]
        if 'packet_ts' in data:
            packet_ts=float(data['packet_ts'])
            if not math.isfinite(packet_ts) or packet_ts<=0:return {}
            native['packet_ts']=packet_ts
        if 'packet_direction' in data:
            if data['packet_direction'] not in ('to_server','to_client','unknown'):return {}
            native['packet_direction']=data['packet_direction']
        states=('LISTEN','SYN_SENT','SYN_RECV','ESTABLISHED','MID_STREAM_SENT','MID_STREAM_RECV',
                'FIN_WAIT1','FIN_WAIT2','CLOSE_WAIT','CLOSING','LAST_ACK','TIME_WAIT','CLOSED','STATE_NONE')
        state=''
        if proto=='TCP':
            values=[data.get(key,-1) for key in ('client_state','server_state')]
            if any(type(value) is not int or not -1<=value<len(states) for value in values):return {}
            state=' '.join(prefix+states[value] for prefix,value in zip(('CLT_TCP_','SRV_TCP_'),values) if value>=0)
        return dict(timestamp=timestamp(ts),event_type='session',src_ip=source,src_port=data['sport'],
            dest_ip=target,dest_port=data['dport'],proto=proto,
            app_proto=native['appid_service'],snort_native=native,
            flow=dict(age=last-first,state=state,pkts_toserver=data['orig_pkts'],pkts_toclient=data['resp_pkts']))
    except (KeyError,ValueError,TypeError,OverflowError):return {}


def native_event(envelope, metadata=None):
    """Map native values into the console's internal event model, retaining raw input."""
    if envelope.get('engine')=='snort_session':
        return session_observation(envelope)
    if envelope.get('engine')=='quic_observer':
        from quic_observer import normalized_event
        return normalized_event(envelope)
    if envelope.get('engine') != 'snort3' or not isinstance(envelope.get('data'), dict):
        return envelope
    data = envelope['data']
    kind = envelope.get('kind') or record_kind(data)
    if kind == 'decoder':
        # alert_json seconds is integral; timestamp carries the subsecond suffix.
        fraction = re.search(r'\.(\d+)$', str(data.get('timestamp', '')))
        stamp = str(data.get('seconds', '')) + ('.'+fraction[1] if fraction else '')
        data = dict(data, ts=stamp, **{'id.orig_h':data.get('src_addr',''),
                    'id.orig_p':data.get('src_port'), 'id.resp_h':data.get('dst_addr',''),
                    'id.resp_p':data.get('dst_port')})
        kind = 'notice'
    stamp = timestamp(data.get('ts'))
    if not kind or not stamp:
        return {}
    origin, responder = data.get('id.orig_h', ''), data.get('id.resp_h', '')
    uid = str(data.get('uid', ''))
    if not re.fullmatch(r'\d{1,20}', uid):
        uid = ''
    session_id = str(data.get('session_id') or '')
    if not re.fullmatch(r'[0-9a-f]{32}:[0-9a-f]{16}',session_id) or session_id.endswith(':0000000000000000'):
        session_id = ''
    event_type = {'conn':'flow', 'ssl':'tls', 'file':'fileinfo', 'weird':'anomaly', 'notice':'alert'}.get(kind, kind)
    obj = dict(event_type=event_type, timestamp=stamp, src_ip=origin,
               src_port=data.get('id.orig_p'), dest_ip=responder, dest_port=data.get('id.resp_p'),
               proto=str(data.get('proto', '')).upper(), app_proto=data.get('service') or (kind if kind not in ('notice','weird','conn') else ''),
               session_id=session_id, snort_native={
                   NATIVE_FIELDS[key]: str(value) if key in ('uid','fuid') else value
                   for key, value in data.items() if key in NATIVE_FIELDS})
    obj['snort_native']['native_uid'] = uid
    obj['snort_native']['session_id'] = session_id
    if kind == 'notice':
        gid, sid = int(data.get('gid') or 0), int(data.get('sid') or 0)
        details = (metadata.get((gid,sid),{}) if metadata is not None else
                   envelope['rule_metadata'] if isinstance(envelope.get('rule_metadata'),dict) else
                   rule_metadata().get((gid,sid),{}))
        actual = str(data.get('action') or '').lower()
        blocked = actual in ('drop', 'block', 'reject', 'reset', 'blacklist')
        suppressed = data.get('alert_suppressed') == 1
        if suppressed and not blocked:
            return {}
        obj['alert'] = dict(gid=gid, signature_id=sid, rev=data.get('rev'),
            signature=data.get('msg') or '', severity=data.get('priority',details.get('severity', 0)),
            category=data.get('class',details.get('category', '')), action='blocked' if blocked else 'allowed',
            metadata=details.get('metadata', {}))
        if blocked:
            obj.update(event_type='drop', drop={'reason':actual})
            if suppressed:
                obj['drop']['alert_suppressed'] = True
    elif kind == 'weird':
        obj['anomaly'] = dict(type=data.get('source', ''), event=data.get('msg', ''))
    elif kind == 'conn':
        duration = float(data.get('duration') or 0)
        # Extractor ts belongs to the packet that triggers logging, including
        # deferred cleanup. It is not the flow's first/last packet timestamp.
        obj['flow'] = dict(age=duration,
            state=data.get('conn_state', ''), pkts_toserver=data.get('orig_pkts'),
            pkts_toclient=data.get('resp_pkts'), bytes_toserver=data.get('orig_bytes'),
            bytes_toclient=data.get('resp_bytes'))
    elif kind == 'http':
        obj['http'] = dict(http_method=data.get('method'), hostname=data.get('host'), url=data.get('uri'),
            http_user_agent=data.get('user_agent'), http_refer=data.get('referrer'),
            protocol=('HTTP/'+str(data['version']) if data.get('version') else ''), status=data.get('status_code'), length=data.get('response_body_len'),
            http_content_type=data.get('resp_mime_types'))
        obj['tx_id'] = data.get('trans_depth')
    elif kind == 'dns':
        obj['dns'] = dict(type='response', rrname=data.get('query'), rrtype=data.get('qtype_name') or data.get('qtype'),
            rcode=data.get('rcode_name') or data.get('rcode'), answers=[{'rdata':str(x)} for x in (data.get('answers', []) if isinstance(data.get('answers'), list) else [data['answers']] if data.get('answers') else [])])
        obj['tx_id'] = data.get('trans_id')
        ttls=data.get('TTLs',[])
        if isinstance(ttls,str):ttls=re.split(r'[,\s]+',ttls)
        if isinstance(ttls,list):
            values=[int(value) for value in ttls[:128] if re.fullmatch(r'[0-9]{1,10}',str(value)) and int(value)<=2147483647]
            if values:obj['snort_native']['dns_ttl']=min(values)
    elif kind == 'ssl':
        obj['tls'] = dict(sni=data.get('server_name'), version=data.get('version'),
                          subject=data.get('subject'), issuerdn=data.get('issuer'))
    elif kind == 'file':
        obj['fileinfo'] = dict(filename=data.get('filename'), magic=data.get('mime_type'),
                              size=data.get('total_bytes'), sha256=data.get('sha256'))
    else:
        obj[kind] = data
    return obj


class SnortControl:
    """Only fixed application operations reach the privileged engine socket."""
    MAX_RESPONSE = 8 << 20
    PROMPT = b'o")~ '

    def __init__(self, path=SOCKET):
        self.path = path

    def command(self, text, timeout=10):
        deadline = time.monotonic() + timeout
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            channel.settimeout(min(timeout, 2))
            channel.connect(self.path)
            def read_prompt():
                output = bytearray()
                while time.monotonic() < deadline:
                    channel.settimeout(max(.01, deadline-time.monotonic()))
                    part = channel.recv(65536)
                    if not part:
                        raise RuntimeError('Snort control channel closed')
                    output.extend(part)
                    if len(output) > self.MAX_RESPONSE:
                        raise RuntimeError('Snort control response exceeds limit')
                    if self.PROMPT in output:
                        return output.decode('utf-8', 'replace')
                raise TimeoutError('Snort control deadline exceeded')
            read_prompt()
            channel.sendall(text.encode('ascii') + b'\n')
            return read_prompt()

    def call(self, commands, timeout=10):
        result = {}
        try:
            for command in commands:
                if not isinstance(command, str):
                    raise ValueError('Engine operation must be a fixed name')
                if command == 'ruleset-reload-rules':
                    before = self.command('show_config_generation()', timeout)
                    reply = self.command('reload_config()', timeout)
                    if re.search(r'fail|error|restart required', reply, re.I):
                        raise RuntimeError('Snort rejected configuration reload')
                    deadline = time.monotonic() + timeout
                    while time.monotonic() < deadline:
                        after = self.command('show_config_generation()', min(5, timeout))
                        if after != before:
                            result[command] = {'confirmed':True}
                            break
                        time.sleep(.2)
                    else:
                        raise TimeoutError('Snort reload generation did not advance')
                elif command == 'appid-reload-detectors':
                    reply = self.command('appid.reload_detectors()', timeout)
                    if re.search(r'fail|error|pending|retry',reply,re.I) or 'swapping detectors configuration' not in reply:
                        raise RuntimeError('Snort did not confirm AppID detector reload')
                    # Snort returns the next prompt after the worker swap and
                    # scratch update finish; an early acknowledgement is insufficient.
                    result[command] = {'confirmed':True}
                elif command == 'dump-counters':
                    raw = self.command('dump_stats("json")', timeout)
                    start = raw.find('{')
                    if start < 0:
                        raise RuntimeError('Snort did not return JSON counters')
                    stats = json.JSONDecoder().raw_decode(raw[start:])[0]
                    groups = {}
                    for section in stats.get('sections', []):
                        for group in section.get('groups', []):
                            counters = groups.setdefault(group['name'], {})
                            for counter in group.get('counters', []):
                                counters[counter['name']] = counter['value']
                    daq, actions = groups.get('daq', {}), groups.get('ips_actions', {})
                    result[command] = dict(native=groups,
                        decoder=dict(pkts=daq.get('received', 0), bytes=daq.get('rx_bytes', 0)),
                        capture=dict(kernel_drops=daq.get('dropped', 0)),
                        ips=dict(accepted=daq.get('allow', 0), blocked=daq.get('block', 0)+daq.get('blacklist', 0),
                                 rejected=actions.get('reject', 0),
                                 drop_reason=dict(rules=actions.get('block', 0)+actions.get('drop', 0))),
                        flow=dict(memuse=None), tcp=dict(reassembly_memuse=None,memory=groups.get('stream_tcp',{}).get('memory')))
                elif command == 'version':
                    self.command('show_config_generation()', timeout)
                    manifest = json.loads(Path(PREFIX+'/engine-manifest.json').read_text())
                    result[command] = manifest['sources']['snort']['version']
                elif command in ('running-mode','capture-mode'):
                    result[command] = 'inline' if command == 'running-mode' else 'NFQ'
                elif command == 'ruleset-stats':
                    self.command('show_config_generation()', timeout)
                    result[command] = {'rules_loaded':len(rule_metadata()),'rules_loaded_source':'rule_files', 'rules_failed':None, 'rules_skipped':None}
                elif command in ('uptime','ruleset-reload-time'):
                    result[command] = None
                else:
                    raise ValueError('Unsupported engine operation')
        except (OSError, ValueError, RuntimeError, TimeoutError) as exc:
            result['__error__'] = str(exc)
        return result
