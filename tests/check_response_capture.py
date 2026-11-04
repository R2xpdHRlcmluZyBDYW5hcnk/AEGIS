"""Inspect IPv6 TCP resets in a local pcap without displaying device addresses."""
import argparse
import json
from pathlib import Path
import struct


def inspect(path,server_port=80):
    with Path(path).open('rb') as capture:
        return _inspect(capture,server_port)


def _inspect(capture,server_port):
    raw=capture.read(24)
    formats={b'\xd4\xc3\xb2\xa1':'<',b'\xa1\xb2\xc3\xd4':'>',b'\x4d\x3c\xb2\xa1':'<',b'\xa1\xb2\x3c\x4d':'>'}
    if len(raw)<24 or raw[:4] not in formats:raise ValueError('Expected a classic pcap file')
    order=formats[raw[:4]];link=struct.unpack_from(order+'I',raw,20)[0]
    if link not in (1,113,276):raise ValueError('Unsupported pcap link type')
    packets=resets=truncated=0;directions=set();checksums=[]
    while record:=capture.read(16):
        if len(record)!=16:raise ValueError('Truncated pcap record')
        _,_,size,_=struct.unpack(order+'IIII',record)
        if size>1<<20:raise ValueError('Captured packet exceeds inspection budget')
        data=capture.read(size)
        if len(data)!=size:raise ValueError('Truncated captured packet')
        header={1:14,113:16,276:20}[link]
        if len(data)<header+60 or data[header]>>4!=6 or data[header+6]!=6:continue
        tcp=header+40;source,destination=struct.unpack_from('!HH',data,tcp)
        if server_port not in (source,destination):continue
        packets+=1
        if not data[tcp+13]&4:continue
        resets+=1;directions.add('to_server' if destination==server_port else 'to_client')
        length=struct.unpack_from('!H',data,header+4)[0];segment=data[tcp:tcp+length]
        if len(segment)!=length:truncated+=1;continue
        pseudo=data[header+8:header+40]+struct.pack('!I3xB',length,6)+segment
        if len(pseudo)%2:pseudo+=b'\0'
        total=sum(struct.unpack('!%dH'%(len(pseudo)//2),pseudo))
        while total>>16:total=(total&65535)+(total>>16)
        checksums.append(total==65535)
    return dict(ipv6_tcp_packets=packets,resets=resets,rst_directions=sorted(directions),
                rst_checksums_valid=bool(checksums) and not truncated and all(checksums),truncated_resets=truncated)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture',type=Path);parser.add_argument('--server-port',type=int,default=80)
    args=parser.parse_args();print(json.dumps(inspect(args.capture,args.server_port),indent=2))
