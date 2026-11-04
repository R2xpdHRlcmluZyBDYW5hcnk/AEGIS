"""Bounded QUIC observations from Wireshark; never implements a QUIC decoder."""
import argparse
from collections import OrderedDict
import csv
from datetime import datetime,timezone
import io
from ipaddress import ip_address
import json
import math
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import subprocess
import time

FIELDS=('frame.number','frame.time_epoch','ip.src','ipv6.src','udp.srcport','ip.dst','ipv6.dst',
        'udp.dstport','udp.length','quic.connection.number','quic.dcid','quic.scid','quic.version',
        'tls.handshake.type','tls.handshake.extensions_server_name','tls.handshake.extensions_alpn_str')
RESET_PACKETS=100000
OBSERVER_FIELDS={key:key for key in ('observer','quic_cids','quic_paths','coverage')}


def stamp(value):
    return datetime.fromtimestamp(value,timezone.utc).isoformat(timespec='microseconds')


def values(text):
    return list(dict.fromkeys(part for part in text.split(',') if part))


def packet(line):
    row=next(csv.reader([line],delimiter='\t'))
    if len(row)!=len(FIELDS):raise ValueError('Invalid observer field count')
    row=dict(zip(FIELDS,row))
    number=int(row['frame.number']);ts=float(row['frame.time_epoch'])
    if number<1 or not math.isfinite(ts) or ts<=0:raise ValueError('Invalid observer timestamp')
    connections=values(row['quic.connection.number'])
    # A marker for the first frame after -M is emitted even when it is not
    # QUIC. Without it a filtered-out reset could alias a reused connection ID.
    if len(connections)!=1 or not connections[0].isdigit():
        return dict(frame=number,ts=ts,connection=None)
    source=str(ip_address(row['ip.src'] or row['ipv6.src']))
    target=str(ip_address(row['ip.dst'] or row['ipv6.dst']))
    sport,dport=int(row['udp.srcport']),int(row['udp.dstport'])
    if not 0<=sport<=65535 or not 0<=dport<=65535:raise ValueError('Invalid observer port')
    dcids=[cid.replace(':','').lower() for cid in values(row['quic.dcid'])]
    scids=[cid.replace(':','').lower() for cid in values(row['quic.scid'])]
    cids=dcids+scids
    if any(not re.fullmatch(r'(?:[0-9a-f]{2}){1,20}',cid) for cid in cids):raise ValueError('Invalid QUIC CID')
    return dict(frame=number,ts=ts,source=(source,sport),target=(target,dport),
                connection=int(connections[0]),cids=cids[:16],dcids=dcids[:8],scids=scids[:8],version=values(row['quic.version'])[:2],
                client_hello='1' in values(row['tls.handshake.type']),
                sni=row['tls.handshake.extensions_server_name'][:253],
                alpn=[part[:64] for part in values(row['tls.handshake.extensions_alpn_str'])[:8]],
                size=max(0,min(65535,int(row['udp.length'].split(',')[0]))-8))


class Tracker:
    def __init__(self,emit,capacity=4096,interval=30,idle=120):
        self.emit=emit;self.capacity=capacity;self.interval=interval;self.idle=idle
        self.prefix=secrets.token_hex(16);self.sequence=0;self.states=OrderedDict();self.last_frame=0

    def observe(self,item):
        if item is None:return
        # -M resets Wireshark state after each packet block. Never reuse its
        # numeric connection ID across reset blocks or decoder processes.
        if self.last_frame and (item['frame']<=self.last_frame or
                (item['frame']-1)//RESET_PACKETS!=(self.last_frame-1)//RESET_PACKETS):
            for state in self.states.values():self.flush(state,'decoder_state_reset')
            self.states.clear()
        self.last_frame=item['frame']
        if item['connection'] is None:return
        key=item['connection']
        ts=item['ts'];state=self.states.get(key)
        if state is None:
            if len(self.states)>=self.capacity:
                _,old=self.states.popitem(last=False);self.flush(old,'state_capacity')
            self.sequence+=1
            state=dict(session_id=self.prefix+':'+format(self.sequence,'016x'),first=ts,last=ts,
                       origin=item['source'],peer=item['target'],client=None,sni='',alpn=[],version=[],
                       cids=[],paths=[],a_packets=0,b_packets=0,a_bytes=0,b_bytes=0,dirty=False,
                       published=0,limited=False,a_cids=set(),b_cids=set(),unknown_packets=0)
            self.states[key]=state
        changed=not state['published']
        if item['client_hello']:
            for field in ('sni','alpn','version'):
                if item[field] and state[field]!=item[field]:state[field]=item[field];changed=True
        to_a=bool(set(item['dcids'])&state['a_cids']);to_b=bool(set(item['dcids'])&state['b_cids'])
        reverse=to_a if to_a!=to_b else item['target']==state['origin'] or item['source']==state['peer']
        known=to_a!=to_b or item['source'] in (state['origin'],state['peer']) or item['target'] in (state['origin'],state['peer'])
        side='b' if reverse else 'a'
        if known:
            state[side+'_packets']+=1;state[side+'_bytes']+=item['size']
            own=state[side+'_cids'];other=state[('a' if reverse else 'b')+'_cids']
            own.update(item['scids'][:max(0,16-len(own))]);other.update(item['dcids'][:max(0,16-len(other))])
            if item['client_hello']:state['client']=state['peer'] if reverse else state['origin']
        else:state['unknown_packets']+=1
        path=(item['target'],item['source']) if reverse else (item['source'],item['target'])
        if path not in state['paths']:
            if len(state['paths'])<8:state['paths'].append(path);changed=True
            else:state['limited']=True
        for cid in item['cids']:
            if cid not in state['cids']:
                if len(state['cids'])<16:state['cids'].append(cid);changed=True
                else:state['limited']=True
        state['first']=min(state['first'],ts);state['last']=max(state['last'],ts);state['dirty']=True;self.states.move_to_end(key)
        if changed or ts-state['published']>=self.interval:self.flush(state,'update')
        self.expire(ts)

    def expire(self,ts):
        for key in list(self.states):
            if ts-self.states[key]['last']>self.idle:self.flush(self.states.pop(key),'observation_idle')
            else:break

    def flush(self,state,reason):
        if not state['dirty']:return
        data={k:state[k] for k in ('session_id','first','last','sni','alpn','version','cids','paths',
                                  'a_packets','b_packets','a_bytes','b_bytes','limited','unknown_packets')}
        data.update(origin=state['origin'],peer=state['peer'],client=state['client'],reason=reason)
        self.emit(dict(engine='quic_observer',data=data))
        state['dirty']=False;state['published']=state['last']

    def close(self):
        for state in self.states.values():self.flush(state,'observer_stopped')
        self.states.clear()


def normalized_event(envelope):
    """Whitelisted adapter into the console schema; source identities stay separate."""
    data=envelope.get('data') or {}
    identity=data.get('session_id','')
    if not re.fullmatch(r'[0-9a-f]{32}:[0-9a-f]{16}',identity):return {}
    start,end=float(data['first']),float(data['last'])
    if not all(math.isfinite(t) and t>0 for t in (start,end)) or end<start:return {}
    source,peer=data['origin'],data['peer']
    for endpoint in (source,peer):
        ip_address(endpoint[0])
        if not isinstance(endpoint[1],int) or not 0<=endpoint[1]<=65535:return {}
    offered=[str(value)[:64] for value in data.get('alpn',[])[:8]]
    cids=[value for value in data.get('cids',[])[:16] if re.fullmatch(r'(?:[0-9a-f]{2}){1,20}',value)]
    paths=data.get('paths',[])[:8]
    extensions=dict(session_id=identity,observer='Wireshark QUIC',quic_cids=','.join(cids),
                    quic_paths=json.dumps(paths,separators=(',',':')),coverage='passive_visible')
    quic=dict(sni=str(data.get('sni',''))[:253],version=','.join(data.get('version',[])[:2]),
              alpn_offered=offered,visible_paths=paths,connection_ids=cids,
              observation_end=data.get('reason','update'),partial=True,limits_reached=bool(data.get('limited')),
              packets_a_to_b=data['a_packets'],packets_b_to_a=data['b_packets'],direction_unknown=data.get('unknown_packets',0))
    obj=dict(timestamp=stamp(end),event_type='quic',src_ip=source[0],src_port=source[1],
             dest_ip=peer[0],dest_port=peer[1],proto='UDP',app_proto='quic',quic=quic,
             tls=dict(sni=quic['sni'],client_alpns=offered),observer_fields=extensions)
    client=data.get('client')
    if client and not data.get('unknown_packets'):
        reverse=tuple(client)!=tuple(source)
        a,b=('b','a') if reverse else ('a','b')
        obj['flow']=dict(start=stamp(start),end=stamp(end),age=end-start,state='observed',
                         bytes_toserver=data[a+'_bytes'],bytes_toclient=data[b+'_bytes'],
                         pkts_toserver=data[a+'_packets'],pkts_toclient=data[b+'_packets'])
    return obj


def command(interface=None,pcap=None,binary='tshark'):
    args=[binary,'-n','-l','-M',str(RESET_PACKETS)]
    args+=['-r',str(pcap)] if pcap else ['-i',interface,'-f','udp','-B','4','-s','65535']
    args+=['-Y','quic || frame.number == 1','-T','fields','-E','separator=\t','-E','quote=d']
    for field in FIELDS:args+=['-e',field]
    return args


def run(args):
    from log_storage import log_paths,validate_log_storage
    validate_log_storage()
    output=Path(args.output) if args.output else log_paths()[0]/'0_quic_observer.json'
    if output.is_symlink():raise ValueError('Observer output cannot be a symbolic link')
    def emit(value):
        line=json.dumps(value,separators=(',',':')).encode()+b'\n'
        with output.open('ab',buffering=0) as handle:
            remaining=memoryview(line)
            while remaining:remaining=remaining[handle.write(remaining):]
            os.fsync(handle.fileno())
    tracker=Tracker(emit);stopping=False
    def stop(*_):
        nonlocal stopping
        stopping=True
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    capture=None
    if not args.pcap:
        capture=subprocess.Popen(['dumpcap','-i',args.interface,'-f','udp','-B','4','-s','65535','-w','-','-q'],
                                 stdout=subprocess.PIPE,start_new_session=True,bufsize=0)
    try:
        process=subprocess.Popen(command(pcap=args.pcap or '-',binary=args.tshark),
                                 stdin=capture.stdout if capture else subprocess.DEVNULL,
                                 stdout=subprocess.PIPE,start_new_session=True,bufsize=0)
    except Exception:
        if capture:
            capture.terminate();capture.wait(timeout=5);capture.stdout.close()
        raise
    if capture:capture.stdout.close()
    buffer=b'';selector=selectors.DefaultSelector();selector.register(process.stdout,selectors.EVENT_READ)
    try:
        while not stopping:
            if not selector.select(timeout=1):continue
            chunk=os.read(process.stdout.fileno(),65536)
            if not chunk:break
            buffer+=chunk
            while b'\n' in buffer:
                line,buffer=buffer.split(b'\n',1)
                if len(line)>32768:raise ValueError('Observer record exceeds limit')
                try:item=packet(line.decode('utf-8','strict'))
                except (ValueError,UnicodeError):continue
                tracker.observe(item)
            if len(buffer)>32768:raise ValueError('Observer record exceeds limit')
        if not stopping and process.wait(timeout=10)!=0:raise RuntimeError('QUIC decoder exited unsuccessfully')
    finally:
        try:tracker.close()
        finally:
            selector.close();process.stdout.close()
            for child in (process,capture):
                if child is None:continue
                if child.poll() is None:
                    try:os.killpg(child.pid,signal.SIGTERM)
                    except ProcessLookupError:pass
                    try:child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        try:os.killpg(child.pid,signal.SIGKILL)
                        except ProcessLookupError:pass
                        child.wait()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--interface');parser.add_argument('--pcap',type=Path)
    parser.add_argument('--output',type=Path);parser.add_argument('--tshark',default='tshark')
    parser.add_argument('--config',type=Path);parser.add_argument('--prepare-output',action='store_true')
    args=parser.parse_args()
    if args.prepare_output:
        import pwd
        from log_storage import log_paths,validate_log_storage
        validate_log_storage();path=log_paths()[0]/'0_quic_observer.json';user=pwd.getpwnam('ips-quic')
        descriptor=os.open(path,os.O_CREAT|os.O_APPEND|os.O_WRONLY|os.O_NOFOLLOW,0o644)
        try:os.fchown(descriptor,user.pw_uid,user.pw_gid)
        finally:os.close(descriptor)
        return
    if args.config:
        config=json.loads(args.config.read_text())
        args.interface=config['interface']
    if bool(args.interface)==bool(args.pcap):parser.error('Choose one capture interface or local PCAP')
    run(args)


if __name__=='__main__':main()
