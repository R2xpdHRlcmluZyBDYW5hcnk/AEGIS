#!/usr/bin/env python3
"""Linux development host only: real DynamicUser/credentials/IPC with synthetic data.

Run as root on a local Linux development system with systemd. Never run on the router.
All units, the temporary group and synthetic state are removed in finally blocks.
"""
import contextlib
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]


def run(*args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True)


def main():
    if os.geteuid() != 0 or not Path('/run/systemd/system').is_dir():
        raise SystemExit('Run on a local Linux development host as root with systemd')
    if Path('/etc/ips-web.conf').exists():
        raise SystemExit('Refusing to run on an installed IPS host')
    token = 'aegis-check-' + uuid.uuid4().hex[:12]
    group = token
    base = Path(tempfile.mkdtemp(prefix=token + '-', dir='/run'))
    os.chmod(base, 0o755)
    unit_names = [token + '-manager.service', token + '-web.service']
    state_name = token + '-web'
    try:
        run('groupadd', '--system', group)
        for name in ('ips-web', 'ips_control.py', 'runtime_status.py','history_reset.py','rule_drafts.py','snort_engine.py','snort_rules.py','native_rules.py','rule_sources.py','rule_identity.py','rule_inventory.py'):
            shutil.copy2(ROOT / name, base / name)
        for name in ('etc', 'rules', 'logs', 'manager-state', 'static'):
            (base / name).mkdir(mode=0o755)
        (base / 'static/index.html').write_text('<html>Fixture</html>')
        (base / 'logs/eve.json').write_text('')
        (base / 'logs/stats.log').write_text('')
        with contextlib.closing(socket.socket()) as listener:
            listener.bind(('127.0.0.1', 0)); port = listener.getsockname()[1]
        config = dict(bind='127.0.0.1', port=port, user='admin', static_dir=str(base / 'static'),
                      password_sha256=hashlib.sha256(b'fixture-password').hexdigest())
        config_path = base / 'web.conf'
        config_path.write_text(json.dumps(config)); config_path.chmod(0o600)
        constants = {}
        for name in ('THRESHOLD_CONF', 'SUPPRESS_LUA', 'DISABLE_CONF', 'DROP_CONF', 'MODIFY_CONF', 'ACTION_CONF', 'SNORT_CONF'):
            constants[name] = str(base / 'etc' / name)
            Path(constants[name]).write_text('')
        for name in ('RULES_FILE', 'LOCAL_RULES', 'BAN_RULES', 'BAN_STORE', 'BAN_DETECTOR','HUNT_RULES'):
            constants[name] = str(base / 'rules' / name)
            Path(constants[name]).write_text('[]' if name == 'BAN_STORE' else '')
        Path(constants['RULES_FILE']).write_text('alert ip any any -> any any (msg:"fixture"; sid:123; rev:1;)\n')
        constants['RULE_SCHEDULE'] = str(base / 'manager-state/schedule.json')
        constants['EVE'] = str(base / 'logs/eve.json')
        constants['STATS_LOG'] = str(base / 'logs/stats.log')
        constants['SNORT_LOG'] = str(base / 'logs/snort.log')
        constants['SOURCES_DIR'] = str(base / 'sources')
        constants['UPDATE_CACHE_DIR'] = str(base / 'cache')
        constants['DIST_RULES_DIR'] = str(base / 'etc/rules')
        Path(constants['UPDATE_CACHE_DIR']).mkdir()
        (Path(constants['UPDATE_CACHE_DIR'])/'fixture-runtime.rules').write_text(Path(constants['RULES_FILE']).read_text())
        prelude = '''import importlib.machinery, importlib.util, sys, os, threading, grp
from pathlib import Path
base=Path(__file__).parent
sys.path.insert(0,str(base))
loader=importlib.machinery.SourceFileLoader('runtime_fixture',str(base/'ips-web'))
spec=importlib.util.spec_from_loader(loader.name,loader)
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;loader.exec_module(m)
'''
        manager_code = prelude + 'constants=' + repr(constants) + '''
for k,v in constants.items():setattr(m,k,v)
from ips_control import Manager, Server, Jobs
m.Snort.call=lambda self, commands, timeout=10: {name:{} for name in commands}
m.nft_query_table=lambda family,table: {}
Jobs.run=lambda self,arguments,job,timeout=600: None
manager=Manager(m,str(base/'manager-state'))
(base/'control.sock').unlink(missing_ok=True)
with Server(str(base/'control.sock'),manager) as server:
 os.chown(base/'control.sock',0,grp.getgrnam(GROUP).gr_gid);os.chmod(base/'control.sock',0o660)
 manager.runtime.start(threading.Event(),base/'status.json')
 threading.Thread(target=manager.run_schedule,args=(threading.Event(),),daemon=True).start()
 server.serve_forever()
'''.replace('GROUP', repr(group))
        (base / 'manager.py').write_text(manager_code)
        (base / 'web.py').write_text(prelude + 'import ips_control\nips_control.SOCKET=' + repr(str(base / 'control.sock')) + '\n' +
            'm.EVE=' + repr(constants['EVE']) + '\nm.STATS_LOG=' + repr(constants['STATS_LOG']) + '\n' +
            'sys.exit(m.main())\n')
        manager_unit = f'''[Unit]
Description=Local synthetic rule manager test
[Service]
Group={group}
ExecStart=/usr/bin/python3 -B {base}/manager.py
ProtectSystem=strict
ReadWritePaths={base}
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_ADMIN
'''
        web_unit = f'''[Unit]
Description=Local synthetic isolated Web test
[Service]
ExecStart=/usr/bin/python3 -B {base}/web.py --config %d/web.conf
DynamicUser=yes
SupplementaryGroups={group}
StateDirectory={state_name}
StateDirectoryMode=0700
LoadCredential=web.conf:{config_path}
Environment=IPS_WEB_ISOLATED=1
ProtectSystem=strict
PrivateTmp=yes
NoNewPrivileges=yes
CapabilityBoundingSet=
InaccessiblePaths={base}/rules {base}/etc {base}/manager-state
'''
        for unit, content in zip(unit_names, (manager_unit, web_unit)):
            Path('/run/systemd/system', unit).write_text(content)
        run('systemctl', 'daemon-reload')
        run('systemctl', 'start', unit_names[0])
        for _ in range(100):
            if (base / 'control.sock').exists(): break
            time.sleep(.05)
        run('systemctl', 'start', unit_names[1])
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(jar))
        url = 'http://127.0.0.1:' + str(port)
        def request(path, body=None):
            headers = {'X-Requested-With':'ips-web'}
            raw = None if body is None else json.dumps(body).encode()
            with opener.open(urllib.request.Request(url+path,raw,headers), timeout=10) as response:
                return json.load(response)
        for _ in range(100):
            try:
                if request('/healthz')['ok']: break
            except OSError: time.sleep(.05)
        else: raise RuntimeError('Fixture Web did not start')
        login = urllib.parse.urlencode(dict(username='admin', password='fixture-password')).encode()
        with opener.open(url+'/login', login) as response: response.read()
        summary = request('/api/rules')
        assert summary['rule_manager'] is True
        setting = dict(enabled=True,frequency='weekly',weekday=4,time='06:12')
        assert request('/api/rules/schedule', setting)['ok']
        assert request('/api/rules/schedule')['time'] == '06:12'
        assert request('/api/rules/disable',dict(values=['sid:123']))['ok']
        assert request('/api/rules/suppress',dict(sids=['123']))['ok']
        removable = request('/api/rules/groups?exclude=suppress-remove')['groups']
        assert any(row['name']=='runtime' and row['removable']==1 for row in removable)
        removed = request('/api/rules/suppress-groups/remove',dict(groups=['runtime']))
        assert removed['ok'] and removed['removed']==1, removed
        assert Path(constants['THRESHOLD_CONF']).read_text()==''
        assert request('/api/rules')['pending'] is True
        assert request('/api/actions/status')['state'] == 'idle'
        assert Path(constants['DISABLE_CONF']).read_text() == ''
        run('systemctl', 'restart', unit_names[0])
        for _ in range(100):
            try:
                if request('/api/rules').get('pending'): break
            except OSError:
                pass
            time.sleep(.05)
        assert request('/api/rules')['pending'] is True
        assert request('/api/actions/update',{})['ok']
        for _ in range(100):
            status = request('/api/actions/status')
            if status['state'] != 'running': break
            time.sleep(.02)
        assert status['rc'] == 0 and status['pending'], status
        assert Path(constants['DISABLE_CONF']).read_text() == ''
        assert request('/api/actions/apply',{})['ok']
        for _ in range(100):
            status = request('/api/actions/status')
            if status['state'] != 'running': break
            time.sleep(.02)
        assert status['rc'] == 0, status
        assert request('/api/rules')['pending'] is False
        assert Path(constants['DISABLE_CONF']).read_text().startswith('123')
        pid = int(run('systemctl','show',unit_names[1],'-p','MainPID','--value').stdout)
        proc = dict(line.split(':',1) for line in Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in line)
        assert int(proc['Uid'].split()[0]) != 0
        assert int(proc['CapEff'].strip(),16) == 0
        mountinfo = Path(f'/proc/{pid}/mountinfo').read_text()
        assert str(base/'rules') in mountinfo
        assert not Path(f'/proc/{pid}/root{base}/rules/RULES_FILE').exists()
        state = Path('/var/lib/private',state_name)
        assert (state/'ips-web.db').exists()
        run('systemctl','restart',unit_names[1])
        assert (base/'manager-state/schedule.json').exists()
        print('PASS: real DynamicUser, zero capabilities, protected rules, IPC, persistent drafts, active-only updates, explicit application and schedule')
    except BaseException:
        for unit in unit_names:
            sys.stderr.write(run('journalctl','-u',unit,'--no-pager','-n','25',check=False).stdout)
        raise
    finally:
        for unit in reversed(unit_names):
            run('systemctl','stop',unit,check=False)
            Path('/run/systemd/system',unit).unlink(missing_ok=True)
            run('systemctl','reset-failed',unit,check=False)
        run('systemctl','daemon-reload',check=False)
        for path in (Path('/var/lib')/state_name,):
            if path.is_symlink(): path.unlink()
        private = Path('/var/lib/private')/state_name
        if private.parent == Path('/var/lib/private') and private.name.startswith('aegis-check-') and private.exists():
            shutil.rmtree(private)
        if base.parent == Path('/run') and base.name.startswith(token): shutil.rmtree(base)
        run('groupdel',group,check=False)


if __name__ == '__main__':
    main()
