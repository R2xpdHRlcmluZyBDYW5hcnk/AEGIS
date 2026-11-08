"""Enable the optional passive QUIC observer without restarting detection."""
import argparse
from datetime import datetime,timezone
import grp
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import time

from deployment_support import validate_log_storage,log_paths


def execute(*args):
    return subprocess.run(list(args),check=True,text=True,capture_output=True,timeout=300,
                          env=dict(os.environ,DEBIAN_FRONTEND='noninteractive',
                                   NEEDRESTART_MODE='l',APT_LISTCHANGES_FRONTEND='none'))


def deploy(release,interface):
    if os.geteuid()!=0:raise ValueError('Run as root')
    if not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}',interface) or not (Path('/sys/class/net')/interface).exists():
        raise ValueError('Choose an existing capture interface')
    release=Path(release);validate_log_storage()
    spec=json.loads((release/'build_tools/quic-sources.json').read_text())
    binary=release/'ips-quic-observer'
    manifest=json.loads((release/'maintenance-build.json').read_text())
    import hashlib
    if hashlib.sha256(binary.read_bytes()).hexdigest()!=manifest['files']['ips-quic-observer'] or binary.read_bytes()[:4]!=b'\x7fELF':
        raise ValueError('Invalid native observer release')
    if Path('/opt/ips-console/bin/ips-quic-observer').read_bytes()!=binary.read_bytes():
        raise ValueError('Deploy the matching console backend before enabling the observer')
    # Use the target distribution's signed, ABI-compatible security packages.
    # Do not replace system libraries with packages from another Debian suite.
    execute('apt-get','update')
    execute('apt-get','install','--assume-yes','--no-install-recommends','tshark='+spec['package_version'])
    version=execute('tshark','--version').stdout.splitlines()[0]
    found=re.search(r' (\d+)\.(\d+)\.(\d+)\.',version)
    if not found or '.'.join(found.groups())!=spec['version']:raise ValueError('Wireshark version differs from the verified manifest')
    try:pwd.getpwnam('ips-quic')
    except KeyError:execute('useradd','--system','--user-group','--no-create-home','--shell','/usr/sbin/nologin','ips-quic')
    try:grp.getgrnam('wireshark')
    except KeyError:pass
    else:execute('usermod','--append','--groups','wireshark','ips-quic')
    targets={Path('/etc/ips-quic-observer.json'):json.dumps(dict(interface=interface)).encode()+b'\n',
             Path('/etc/systemd/system/ips-quic-observer.service'):(release/'ips-quic-observer.service').read_bytes()}
    rotation=Path('/etc/logrotate.d/ips-snort')
    previous_rotation=rotation.read_bytes()
    needle=b'*alert_json.txt'
    if previous_rotation.count(needle)!=1:raise ValueError('Unexpected native log rotation layout')
    if b'*quic_observer.json' not in previous_rotation:
        targets[rotation]=previous_rotation.replace(needle,needle+b' '+str(log_paths()[0]/'*quic_observer.json').encode(),1)
    backup=Path('/var/backups/ips-console')/('quic-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    backup.mkdir(mode=0o700)
    original={p:p.read_bytes() if p.exists() else None for p in targets}
    for index,(path,data) in enumerate(original.items()):
        if data is not None:(backup/(str(index)+'-'+path.name)).write_bytes(data)
    was_active=subprocess.run(['systemctl','is-active','--quiet','ips-quic-observer'],capture_output=True).returncode==0
    try:
        for path,data in targets.items():
            path.write_bytes(data);os.chmod(path,0o644)
        execute('systemctl','daemon-reload')
        execute('systemctl','enable','ips-quic-observer')
        execute('systemctl','restart','ips-quic-observer')
        time.sleep(2)
        execute('systemctl','is-active','--quiet','ips-quic-observer')
        print(json.dumps(dict(quic_observer_enabled=True,decoder=version,backup=str(backup))))
    except Exception:
        subprocess.run(['systemctl','stop','ips-quic-observer'],capture_output=True,timeout=30)
        for path,data in original.items():
            if data is None:path.unlink(missing_ok=True)
            else:path.write_bytes(data)
        subprocess.run(['systemctl','daemon-reload'],capture_output=True,timeout=30)
        if was_active:subprocess.run(['systemctl','start','ips-quic-observer'],capture_output=True,timeout=30)
        else:subprocess.run(['systemctl','disable','ips-quic-observer'],capture_output=True,timeout=30)
        raise


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--release',type=Path,required=True)
    parser.add_argument('--interface',required=True);args=parser.parse_args();deploy(args.release,args.interface)
