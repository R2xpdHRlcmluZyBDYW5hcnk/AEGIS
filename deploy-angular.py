#!/usr/bin/env python3
"""Target-side atomic static UI upgrade. Does not restart or mutate the backend."""
import argparse
import ctypes
import datetime
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tarfile
import urllib.request
import urllib.parse
from deployment_layout import layout


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def database_snapshot(cfg):
    db=Path(cfg.get('event_db') or '/var/lib/ips-web/snort-ndr.db')
    address=cfg.get('database_url')
    if not address:
        return {'db_inode':db.stat().st_ino,'postgres_identity':None}
    parsed=urllib.parse.urlparse(address)
    params=urllib.parse.parse_qs(parsed.query)
    host=params.get('host',[''])[0]
    port=params.get('port',[''])[0]
    if (parsed.scheme not in ('postgres','postgresql') or parsed.hostname or parsed.password
            or parsed.path!='/aegis' or host not in ('/run/postgresql','/var/run/postgresql') or port!='55432'):
        raise ValueError('Unexpected PostgreSQL deployment endpoint')
    major=str(json.loads((Path(__file__).resolve().parent/'build_tools/postgresql-sources.json').read_text())['postgresqlMajor'])
    query="SELECT system_identifier::text||':'||(SELECT oid::text FROM pg_database WHERE datname=current_database())||':'||COALESCE((SELECT oid::text FROM pg_namespace WHERE nspname='aegis'),'0') FROM pg_control_system()"
    identity=subprocess.check_output(['runuser','-u','postgres','--',f'/usr/lib/postgresql/{major}/bin/psql',
        '-X','-At','-v','ON_ERROR_STOP=1','-h',host,'-p',port,'-d','aegis','-c',query],text=True,timeout=15).strip()
    if not re.fullmatch(r'[0-9]+:[0-9]+:[0-9]+',identity):
        raise ValueError('PostgreSQL database identity is unavailable')
    return {'db_inode':db.stat().st_ino if db.exists() else None,'postgres_identity':identity}


def snapshot(cfg):
    paths = [p for p in Path('/etc/snort').rglob('*') if p.is_file()]
    current=layout()
    paths += [Path(current['config']), Path('/etc/nftables.conf'), Path(current['program_dir'])/'ips-web']
    paths += [p for p in Path('/var/lib/snort/rules').rglob('*') if p.is_file()]
    schedule = Path('/var/lib/snort/ips-rule-schedule.json')
    if schedule.exists():
        paths.append(schedule)
    cron = subprocess.run(['crontab', '-l'], capture_output=True) if shutil.which('crontab') else None
    supervisor = subprocess.run(['systemctl', 'show', 'ips', '-p', 'MainPID', '--value'], capture_output=True)
    return {'files': {str(p): digest(p) for p in paths if p.exists()},
            **database_snapshot(cfg),
            'engine_pid': Path('/run/snort/snort.pid').read_text().strip() if Path('/run/snort/snort.pid').exists() else None,
            'supervisor_pid': supervisor.stdout.decode().strip() if supervisor.returncode == 0 else None,
            'console_pids': subprocess.run(['pgrep', '-f', '^'+re.escape(str(Path(current['program_dir'])/'ips-web'))+r'( |$)'],capture_output=True).stdout.decode().split(),
            'crontab': hashlib.sha256(cron.stdout).hexdigest() if cron is not None else None}


def exchange(first, second):
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(first), -100, os.fsencode(second), 2):
        raise OSError(ctypes.get_errno(), 'Atomic static directory exchange failed; nothing was replaced')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--release', default=str(Path(__file__).resolve().parent))
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Run as root')
    lock = open('/run/ips-angular-deploy.lock', 'w')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    release = Path(args.release).resolve()
    manifest = json.loads((release / 'frontend-build.json').read_text())
    core_names = {'index.html', 'app.js', 'ui.js', 'app.css'}
    names = set(manifest['files'])
    if not core_names <= names or any(not re.fullmatch(r'chunk-[A-Za-z0-9]+\.js', name) for name in names-core_names):
        raise SystemExit('Unexpected UI manifest')
    for name, expected in manifest['files'].items():
        if digest(release / name) != expected:
            raise SystemExit('UI checksum mismatch: ' + name)
    if b'<ndr-root>' not in (release / 'index.html').read_bytes():
        raise SystemExit('Angular root missing')
    cfg = json.loads(Path(layout()['config']).read_text())
    static = Path(cfg.get('static_dir', '/usr/local/share/ips-web'))
    if not static.is_absolute() or static == Path('/') or static.is_symlink() or not static.is_dir():
        raise SystemExit('Expected an existing, absolute, non-symlink static_dir')
    static = static.resolve()
    token = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    backup = Path('/var/backups/ips-angular') / token
    backup.mkdir(parents=True, mode=0o700)
    if backup.stat().st_dev != static.stat().st_dev:
        raise SystemExit('Backup and static_dir must share a filesystem for atomic rollback')
    before = snapshot(cfg)
    preserved_static = {p.relative_to(static).as_posix(): digest(p) for p in static.rglob('*')
                        if p.is_file() and p.name not in names | {'frontend-build.json', 'frontend-licenses.txt'}}
    (backup / 'state.before.json').write_text(json.dumps(before, indent=2))
    # All sensitive backups stay on the router, accessible only by root.
    with tarfile.open(backup / 'settings-before.tar.gz', 'w:gz') as archive:
        for name in before['files']:
            if name != '/usr/local/bin/ips-web':
                archive.add(name, arcname=name.lstrip('/'), recursive=False)
    staged = static.with_name('.' + static.name + '.angular-' + token)
    shutil.copytree(static, staged, copy_function=shutil.copy2)
    for name in names:
        shutil.copy2(release / name, staged / name)
    shutil.copy2(release / 'frontend-build.json', staged / 'frontend-build.json')
    shutil.copy2(release / 'frontend-licenses.txt', staged / 'frontend-licenses.txt')
    os.chmod(staged, static.stat().st_mode & 0o777)
    switched = False
    try:
        exchange(staged, static)
        switched = True
        host = cfg.get('bind', '127.0.0.1')
        if host in ('0.0.0.0', '::'):
            host = '127.0.0.1' if host == '0.0.0.0' else '::1'
        if ':' in host:
            host = '[' + host.strip('[]') + ']'
        url = 'http://%s:%s/healthz' % (host, cfg.get('port', 9000))
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(url, timeout=10) as response:
            assert json.load(response).get('ok'), 'Backend health check failed'
        for name, expected in manifest['files'].items():
            assert digest(static / name) == expected, 'Deployed hash mismatch'
        for name, expected in preserved_static.items():
            assert digest(static / name) == expected, 'Existing asset changed: ' + name
        after = snapshot(cfg)
        for key in ('files', 'db_inode', 'postgres_identity', 'engine_pid', 'supervisor_pid', 'console_pids', 'crontab'):
            assert before[key] == after[key], 'Protected state changed: ' + key
    except BaseException:
        if switched:
            exchange(staged, static)
            shutil.move(str(staged), str(backup / 'failed-ui'))
        raise
    shutil.move(str(staged), str(backup / 'static-before'))
    result = {'ok': True, 'framework': manifest['framework'], 'backup': str(backup),
              'static_dir': str(static), 'configuration_unchanged': True, 'rules_unchanged': True,
              'database_preserved': True,
              'protected_files': len(before['files']), 'existing_icons_and_assets_unchanged': True,
              'engine_pid': after['engine_pid'], 'console_pids': after['console_pids'],
              'no_process_restarts': True, 'files': manifest['files']}
    (backup / 'verification.json').write_text(json.dumps(result, indent=2))
    (backup / 'state.after.json').write_text(json.dumps(after, indent=2))
    rollback = "#!/usr/bin/env python3\nimport ctypes, os\nlibc=ctypes.CDLL(None,use_errno=True)\nr=libc.renameat2(-100,os.fsencode(%r),-100,os.fsencode(%r),2)\nif r: raise OSError(ctypes.get_errno(), 'Rollback exchange failed')\nprint('Previous UI restored; backend and data unchanged')\n" % (str(backup / 'static-before'), str(static))
    (backup / 'rollback.py').write_text(rollback)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
