"""Build an isolated loopback preview and remove its assets when the server stops."""
import os
import platform
from pathlib import Path
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
from build_frontend import build

ROOT = Path(__file__).resolve().parent


def main():
    from build_tools.python_dependencies import environment
    with environment(): return serve()


def serve():
    with tempfile.TemporaryDirectory(prefix='aegis-preview-') as directory:
        build(Path(directory))
        stop=Path(directory)/'fixture.stop'
        command,env=native_fixture_command(directory,stop,19090)
        options=dict(creationflags=subprocess.CREATE_NEW_PROCESS_GROUP|subprocess.CREATE_NO_WINDOW) if platform.system()=='Windows' else dict(start_new_session=True)
        process = subprocess.Popen(command, cwd=ROOT, env=env, **options)
        print('Native Go preview: http://127.0.0.1:19090 (admin / preview-only)',flush=True)
        try:
            process.wait()
        except KeyboardInterrupt:
            pass
        finally:
            stop.touch()
            if process.poll() is None:
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    process.wait()


def native_fixture_command(static,stop,port=19096):
    """Use real Go request paths with an opt-in, local-only synthetic fixture."""
    arguments=['test','-count=1','-v','-timeout=24h','-run=^TestBrowserFixture$','./internal/console']
    env=dict(os.environ)
    if platform.system()=='Windows':
        def linux(path):
            return subprocess.check_output(['wsl','-d','Debian','--','wslpath','-a',str(path).replace('\\','/')],text=True).strip()
        command=['wsl','-d','Debian','--','env','AEGIS_GO_FIXTURE_STATIC='+linux(static),
                 'AEGIS_GO_FIXTURE_STOP='+linux(stop),'AEGIS_GO_FIXTURE_PORT='+str(port),
                 'python3','-B',linux(ROOT/'build_tools/go_backend.py'),'--',*arguments]
    else:
        env.update(AEGIS_GO_FIXTURE_STATIC=str(static),AEGIS_GO_FIXTURE_STOP=str(stop),AEGIS_GO_FIXTURE_PORT=str(port))
        command=[sys.executable,'-B',str(ROOT/'build_tools/go_backend.py'),'--',*arguments]
    return command,env


if __name__ == '__main__':
    main()
