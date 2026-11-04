"""Build an isolated loopback preview and remove its assets when the server stops."""
import os
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
        env = dict(os.environ, NDR_PREVIEW_STATIC_DIR=directory, PYTHONDONTWRITEBYTECODE='1')
        process = subprocess.Popen([sys.executable, '-B', str(ROOT / 'tests/serve_preview.py')], cwd=ROOT, env=env)
        try:
            process.wait()
        except KeyboardInterrupt:
            pass
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == '__main__':
    main()
