"""Run real PostgreSQL/Timescale regressions in an isolated temporary cluster."""
import argparse
from contextlib import contextmanager
import getpass
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]


@contextmanager
def cluster(workspace):
    workspace=Path(workspace).resolve()
    if not workspace.is_relative_to(Path(tempfile.gettempdir()).resolve()):
        raise ValueError('Database test dependencies must stay in the system temporary directory')
    root=workspace/'postgres';root.mkdir(exist_ok=True)
    loader=importlib.util.spec_from_file_location('database_deployer',ROOT/'deploy-postgresql.py')
    deployer=importlib.util.module_from_spec(loader);loader.loader.exec_module(deployer)
    spec=json.loads(deployer.SOURCES.read_text());major=str(spec['postgresqlMajor'])
    bundle=root/'bundle';binaries=bundle/f'usr/lib/postgresql/{major}/bin'
    def run(args,**kwargs): return subprocess.run(args,check=True,**kwargs)
    if not (binaries/'postgres').exists():
        arch=subprocess.check_output(['dpkg','--print-architecture'],text=True).strip()
        sources=root/'repositories.sources'
        sources.write_text('\n'.join(content for _,content in deployer.repository_files(spec,root/'keys',arch))+
            '\nTypes: deb\nURIs: https://deb.debian.org/debian\nSuites: trixie\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n')
        for path in ('lists/partial','archives/partial'): (root/path).mkdir(parents=True,exist_ok=True)
        (root/'status').touch()
        options=['-o','Dir::Etc::sourcelist='+str(sources),'-o','Dir::Etc::sourceparts=-',
            '-o','Dir::State::lists='+str(root/'lists'),'-o','Dir::State::status='+str(root/'status'),
            '-o','Dir::Cache::archives='+str(root/'archives'),'-o','Debug::NoLocking=1',
            '-o','Dir::Cache::pkgcache='+str(root/'pkgcache.bin'),'-o','Dir::Cache::srcpkgcache='+str(root/'srcpkgcache.bin'),
            '-o','APT::Sandbox::User='+getpass.getuser()]
        run(['apt-get',*options,'update','-qq'])
        run(['apt-get',*options,'--download-only','--no-install-recommends','-y','install',
             'postgresql-'+major,'timescaledb-2-postgresql-'+major+'='+spec['timescaledbVersion']+'~debian13-1806'],stdout=subprocess.DEVNULL)
        bundle.mkdir(exist_ok=True)
        for package in (root/'archives').glob('*.deb'): run(['dpkg-deb','-x',str(package),str(bundle)])
    env=dict(os.environ)
    libs=list((bundle/'usr/lib').glob('*-linux-gnu'))+list((bundle/'lib').glob('*-linux-gnu'))
    env['LD_LIBRARY_PATH']=':'.join(map(str,libs))
    with tempfile.TemporaryDirectory(prefix='cluster-',dir=root) as temporary:
        state=Path(temporary);data=state/'data';sockets=state/'socket';sockets.mkdir()
        run([str(binaries/'initdb'),'-D',str(data),'--no-locale','-E','UTF8','--auth-local=trust','--auth-host=reject'],env=env,stdout=subprocess.DEVNULL)
        with (data/'postgresql.conf').open('a') as output:
            output.write("\nlisten_addresses=''\nshared_preload_libraries='timescaledb'\nshared_buffers='32MB'\nwal_compression='zstd'\ntimescaledb.telemetry_level='off'\nmax_parallel_workers_per_gather=0\n")
        run([str(binaries/'pg_ctl'),'-D',str(data),'-l',str(state/'server.log'),'-o',f'-k {sockets} -p 55439','-w','start'],env=env,stdout=subprocess.DEVNULL)
        try:
            def sql(query,database='postgres'):
                return subprocess.check_output([str(binaries/'psql'),'-X','-At','-v','ON_ERROR_STOP=1','-h',str(sockets),'-p','55439','-d',database,'-c',query],env=env,text=True)
            sql('CREATE ROLE aegis_test LOGIN')
            sql('CREATE DATABASE aegis OWNER aegis_test')
            sql('CREATE EXTENSION timescaledb','aegis')
            yield f'postgresql://aegis_test@/aegis?host={sockets}&port=55439&sslmode=disable'
        finally:
            run([str(binaries/'pg_ctl'),'-D',str(data),'-m','immediate','-w','stop'],env=env,stdout=subprocess.DEVNULL)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace');parser.add_argument('command',nargs=argparse.REMAINDER)
    args=parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='aegis-postgres-tests-') as owned:
        workspace=Path(args.workspace or owned)
        with cluster(workspace) as address:
            from go_backend import environment
            with environment(workspace) as (go,env):
                env['AEGIS_TEST_POSTGRES_URL']=address
                command=args.command or ['test','-count=1','-timeout=180s','./...']
                if command and command[0]=='--': command=command[1:]
                subprocess.run([go,*command],cwd=ROOT/'backend',env=env,check=True)
