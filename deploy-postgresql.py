#!/usr/bin/env python3
"""Install the dedicated event database from signed upstream APT repositories."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parent
SOURCES = ROOT/'build_tools/postgresql-sources.json'
PORT = 55432
CLUSTER = 'aegis'
DATABASE_URL = 'postgresql://aegis_web@/aegis?host=/var/run/postgresql&port=55432&sslmode=disable'


def run(args, **kwargs):
    return subprocess.run(args, check=True, text=True, env=dict(os.environ,DEBIAN_FRONTEND='noninteractive',NEEDRESTART_MODE='l'), **kwargs)


def verified_repository_key(repository):
    """Keys are fetched at deployment, never stored in source or release files."""
    with urllib.request.urlopen(repository['keyUrl'], timeout=45) as response:
        key = response.read(1024*1024+1)
    if len(key)>1024*1024:
        raise ValueError('Repository signing key is too large')
    with tempfile.TemporaryDirectory(prefix='aegis-apt-key-') as temporary:
        result=subprocess.run(['gpg','--batch','--homedir',temporary,'--with-colons','--show-keys'],
                              input=key,capture_output=True,check=True)
    primary=[]; awaiting=False
    for line in result.stdout.decode().splitlines():
        fields=line.split(':')
        if fields[0]=='pub': awaiting=True
        elif fields[0]=='sub': awaiting=False
        elif fields[0]=='fpr' and awaiting:
            primary.append(fields[9]);awaiting=False
    if not primary or not set(primary)<=set(repository['primaryFingerprints']):
        raise ValueError('Unrecognized '+repository['name']+' repository signing key; verify the official rotation and update the trusted fingerprint list')
    return key


def repository_files(spec, directory, arch):
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=True)
    # Validate all new trust material before changing any repository settings.
    keys=[verified_repository_key(repo) for repo in spec['repositories']]
    entries=[]
    for repo,key in zip(spec['repositories'],keys):
        keyfile=directory/('ips-'+repo['name']+'.asc')
        keyfile.write_bytes(key);keyfile.chmod(0o644)
        entries.append((repo['name'],f"Types: deb\nURIs: {repo['uri']}\nSuites: {repo['suite']}\nArchitectures: {arch}\nComponents: main\nSigned-By: {keyfile}\n"))
    return entries


def ensure_dependencies():
    parent=Path('/var/lib/ips-deploy');parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='postgresql-apt-',dir=parent) as temporary:
        Path(temporary,'partial').mkdir()
        return _ensure_dependencies(temporary)


def _ensure_dependencies(cache):
    spec=json.loads(SOURCES.read_text())
    release={line.split('=',1)[0]:line.split('=',1)[1].strip('"') for line in Path('/etc/os-release').read_text().splitlines() if '=' in line}
    arch=subprocess.check_output(['dpkg','--print-architecture'],text=True).strip()
    if release.get('VERSION_CODENAME')!='trixie' or arch not in ('arm64','amd64'):
        raise RuntimeError('The event database requires Debian 13 amd64 or arm64')
    # Base tooling comes from the administrator's signed Debian repositories.
    apt=['apt-get','-o','Dir::Cache::archives='+cache]
    run([*apt,'update','-qq'])
    run([*apt,'install','-y','--no-install-recommends','ca-certificates','gpg','libnss-systemd'])
    entries=repository_files(spec,'/usr/share/keyrings',arch)
    for name,content in entries:
        path=Path('/etc/apt/sources.list.d')/('ips-'+name+'.sources')
        path.write_text(content);path.chmod(0o644)
    run([*apt,'update','-qq'])
    major=str(spec['postgresqlMajor'])
    package='postgresql-'+major
    candidate=subprocess.check_output(['apt-cache','policy',package],text=True)
    match=re.search(r'Candidate:\s*(\S+)',candidate)
    if not match or 'apt.postgresql.org' not in candidate or not match[1].startswith(major+'.') or any(x in match[1] for x in ('beta','rc','devel')):
        raise RuntimeError('No stable PostgreSQL package is available from PGDG')
    run(['dpkg','--compare-versions',match[1],'ge',spec['postgresqlMinimum']])
    version=spec['timescaledbVersion']
    available=subprocess.check_output(['apt-cache','madison','timescaledb-2-postgresql-'+major],text=True)
    versions=[line.split('|')[1].strip() for line in available.splitlines() if line.count('|')>=2]
    selected=next((v for v in versions if v.startswith(version+'~')),None)
    if selected is None:raise RuntimeError('The validated TimescaleDB package is unavailable for this architecture')
    previous=subprocess.run(['dpkg-query','-W','-f=${Version}',package],capture_output=True,text=True)
    run([*apt,'install','-y','--no-install-recommends','postgresql-common'])
    cluster_conf=Path('/etc/postgresql-common/createcluster.conf')
    if not cluster_conf.is_file() or cluster_conf.is_symlink() or not stat.S_ISREG(cluster_conf.stat().st_mode):
        raise RuntimeError('Unexpected PostgreSQL cluster creation configuration')
    original=cluster_conf.read_bytes()
    # Suppress only package installation's empty default cluster; restore the
    # administrator's cluster creation policy even when installation fails.
    temporary=re.sub(rb'(?m)^\s*create_main_cluster\s*=.*$',b'create_main_cluster = false',original)
    if temporary==original:temporary+=b'\ncreate_main_cluster = false\n'
    try:
        cluster_conf.write_bytes(temporary)
        run([*apt,'install','-y','--no-install-recommends',package+'='+match[1],
             'postgresql-client-'+major,'timescaledb-2-postgresql-'+major+'='+selected,
             'timescaledb-2-loader-postgresql-'+major+'='+selected])
    finally:
        cluster_conf.write_bytes(original)
    spec['packages_changed']=previous.returncode!=0 or previous.stdout.strip()!=match[1]
    return spec


def psql(major,sql,database='postgres'):
    return subprocess.check_output(['runuser','-u','postgres','--',f'/usr/lib/postgresql/{major}/bin/psql',
       '-X','-v','ON_ERROR_STOP=1','-At','-p',str(PORT),'-d',database,'-c',sql],text=True).strip()


def configure(spec):
    major=str(spec['postgresqlMajor']);directory=Path('/etc/postgresql')/major/CLUSTER
    if not directory.exists():
        run(['pg_createcluster',major,CLUSTER,'--port',str(PORT),'--start-conf=auto','--','--auth-local=peer','--auth-host=scram-sha-256'])
    user=subprocess.check_output(['systemctl','show','ips-web.service','-p','User','--value'],text=True).strip()
    if not re.fullmatch(r'[a-z_][a-z0-9_-]*',user):raise RuntimeError('Console service must have a named isolated user')
    verify_console_identity(user)
    conf=directory/'conf.d/90-aegis.conf';conf.parent.mkdir(exist_ok=True)
    managed=(conf,directory/'pg_hba.conf',directory/'pg_ident.conf')
    before={path:path.read_bytes() if path.exists() else None for path in managed}
    conf.write_text("""# Dedicated AEGIS cluster. Other PostgreSQL clusters are not modified.
listen_addresses = ''
port = 55432
shared_preload_libraries = 'timescaledb'
timescaledb.telemetry_level = 'off'
shared_buffers = '128MB'
work_mem = '4MB'
maintenance_work_mem = '32MB'
max_connections = 20
max_worker_processes = 8
max_parallel_workers = 2
max_parallel_workers_per_gather = 0
timescaledb.max_background_workers = 2
wal_compression = 'zstd'
default_toast_compression = 'lz4'
fsync = on
full_page_writes = on
synchronous_commit = on
checkpoint_timeout = '15min'
checkpoint_completion_target = 0.9
min_wal_size = '80MB'
max_wal_size = '512MB'
log_statement = 'none'
log_min_error_statement = 'panic'
""")
    (directory/'pg_hba.conf').write_text('local all postgres peer\nlocal aegis aegis_web peer map=aegis_console\nlocal aegis aegis_admin peer map=aegis_console\nlocal all all reject\n')
    (directory/'pg_ident.conf').write_text(f'aegis_console {user} aegis_web\naegis_console root aegis_admin\n')
    unit='postgresql@'+major+'-'+CLUSTER+'.service'
    limits=Path('/etc/systemd/system')/(unit+'.d')/'50-ips-parallel.conf'
    if not limits.exists():
        limits.parent.mkdir(parents=True,exist_ok=True)
        cpus=subprocess.check_output(['systemctl','show','ips-web.service','-p','AllowedCPUs','--value'],text=True).strip()
        limits.write_text('[Service]\nCPUQuota=400%\n'+('AllowedCPUs='+cpus+'\n' if cpus else ''))
    run(['systemctl','daemon-reload'])
    run(['systemctl','enable',unit])
    active=subprocess.run(['systemctl','is-active','--quiet',unit],capture_output=True).returncode==0
    if spec.get('packages_changed') or any(before[path]!=path.read_bytes() for path in managed):
        run(['systemctl','restart',unit])
    elif not active:
        run(['systemctl','start',unit])
    for role in ('aegis_web','aegis_admin'):
        psql(major,f"DO $$BEGIN IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='{role}') THEN CREATE ROLE {role} LOGIN; END IF; END$$;")
    psql(major,'GRANT aegis_web TO aegis_admin')
    if not psql(major,"SELECT 1 FROM pg_database WHERE datname='aegis'"):
        psql(major,'CREATE DATABASE aegis OWNER aegis_web')
    psql(major,'CREATE EXTENSION IF NOT EXISTS timescaledb','aegis')
    psql(major,'REVOKE CREATE ON SCHEMA public FROM PUBLIC','aegis')
    psql(major,'ALTER DATABASE aegis SET search_path TO aegis,public')
    aic_setting="SELECT setting FROM pg_settings WHERE name='timescaledb.enable_aic_compression'"
    if not psql(major,aic_setting,'aegis'):
        raise RuntimeError('The installed TimescaleDB extension does not expose adaptive integer compression')
    psql(major,'ALTER DATABASE aegis SET timescaledb.enable_aic_compression TO on')
    if psql(major,aic_setting,'aegis')!='on':
        raise RuntimeError('Adaptive integer compression is not enabled in new AEGIS database sessions')
    return {'database_url':DATABASE_URL,'postgresql_major':int(major),'timescaledb_version':psql(major,"SELECT extversion FROM pg_extension WHERE extname='timescaledb'",'aegis')}


def install():
    if os.geteuid()!=0:raise RuntimeError('Run the PostgreSQL dependency installer as root')
    return configure(ensure_dependencies())


def verify_console_identity(user):
    identity=subprocess.run(['getent','passwd',user],capture_output=True,text=True)
    if identity.returncode!=0 or identity.stdout.split(':',1)[0]!=user:
        raise RuntimeError('Console DynamicUser cannot be resolved; enable the libnss-systemd passwd provider before PostgreSQL peer authentication')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    print(json.dumps(install()))
