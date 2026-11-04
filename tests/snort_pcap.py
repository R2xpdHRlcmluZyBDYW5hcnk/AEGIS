"""Small, entirely synthetic HTTP and DNS capture for native-engine regression."""
import socket
import struct


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    value = sum(struct.unpack('!%dH' % (len(data)//2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return ~value & 65535


def capture(path, tls_hostname=None):
    frames=[]
    client, server=map(socket.inet_aton, ('192.0.2.10','198.51.100.20'))
    def packet(src,dst,proto,payload):
        ip=struct.pack('!BBHHHBBH4s4s',69,0,20+len(payload),len(frames)+1,0,64,proto,0,src,dst)
        ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
        frames.append(bytes.fromhex('0200000000020200000000010800')+ip+payload)
    def tcp(reverse,seq,ack,flags,data=b'',port=80,client_port=45000):
        src,dst=(server,client) if reverse else (client,server)
        sport,dport=(port,client_port) if reverse else (client_port,port)
        header=struct.pack('!HHIIBBHHH',sport,dport,seq,ack,80,flags,65535,0,0)
        total=header+data
        pseudo=src+dst+struct.pack('!BBH',0,6,len(total))
        header=header[:16]+struct.pack('!H',checksum(pseudo+total))+header[18:]
        packet(src,dst,6,header+data)
    request=b'GET /ndr-smoke HTTP/1.1\r\nHost: example.test\r\nUser-Agent: NDR-Test\r\nConnection: close\r\n\r\n'
    response=b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello'
    tcp(False,1,0,2);tcp(True,100,2,18);tcp(False,2,101,16)
    tcp(False,2,101,24,request);tcp(True,101,2+len(request),24,response)
    tcp(False,2+len(request),101+len(response),17)
    tcp(True,101+len(response),3+len(request),17)
    tcp(False,3+len(request),102+len(response),16)
    question=b'\x07example\x04test\0'+struct.pack('!HH',1,1)
    for reverse in (False,True):
        dns=struct.pack('!HHHHHH',1234,0x8180 if reverse else 0x0100,1,1 if reverse else 0,0,0)+question
        if reverse:
            dns+=b'\xc0\x0c'+struct.pack('!HHIH',1,1,60,4)+server
        src,dst=(server,client) if reverse else (client,server)
        udp=struct.pack('!HHHH',53 if reverse else 45001,45001 if reverse else 53,8+len(dns),0)+dns
        packet(src,dst,17,udp)
    if tls_hostname:
        import ssl
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_ecdh_curve("prime256v1")
        connection = context.wrap_bio(incoming, outgoing, server_side=False, server_hostname=tls_hostname)
        try:
            connection.do_handshake()
        except ssl.SSLWantReadError:
            pass
        hello = outgoing.read()
        tcp(False,1,0,2,port=443,client_port=45002)
        tcp(True,100,2,18,port=443,client_port=45002)
        tcp(False,2,101,16,port=443,client_port=45002)
        for offset in range(0,len(hello),1000):
            tcp(False,2+offset,101,24,hello[offset:offset+1000],port=443,client_port=45002)
        import subprocess, tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory(prefix='snort-tls-fixture-') as temporary:
            cert, key = Path(temporary)/'cert.pem', Path(temporary)/'key.pem'
            subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout',str(key),'-out',str(cert),'-subj','/CN=example.test','-days','1'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            server_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.load_cert_chain(cert,key)
            server_in,server_out=ssl.MemoryBIO(),ssl.MemoryBIO()
            server_tls=server_context.wrap_bio(server_in,server_out,server_side=True)
            server_in.write(hello)
            try:
                server_tls.do_handshake()
            except ssl.SSLWantReadError:
                pass
            server_flight=server_out.read()
            for offset in range(0,len(server_flight),1000):
                tcp(True,101+offset,2+len(hello),24,server_flight[offset:offset+1000],port=443,client_port=45002)
            tcp(False,2+len(hello),101+len(server_flight),16,port=443,client_port=45002)
            incoming.write(server_flight)
            try:
                connection.do_handshake()
            except ssl.SSLWantReadError:
                pass
            finished = outgoing.read()
            tcp(False,2+len(hello),101+len(server_flight),24,finished,port=443,client_port=45002)
            server_in.write(finished)
            try:
                server_tls.do_handshake()
            except ssl.SSLWantReadError:
                pass
            response = server_out.read()
            if response:
                tcp(True,101+len(server_flight),2+len(hello)+len(finished),24,response,port=443,client_port=45002)


    with open(path,'wb') as output:
        output.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
        for index,frame in enumerate(frames):
            output.write(struct.pack('<IIII',1700000000,index*10000,len(frame),len(frame)))
            output.write(frame)
