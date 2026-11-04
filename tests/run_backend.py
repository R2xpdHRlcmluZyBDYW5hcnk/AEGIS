"""Run backend checks with checksum-pinned dependencies in a temporary directory."""
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from build_tools.python_dependencies import environment


if __name__=='__main__':
    arguments=sys.argv[1:] or ['discover','-s','tests','-q']
    with environment():
        result=subprocess.run([sys.executable,'-B','-m','unittest',*arguments],cwd=ROOT)
    raise SystemExit(result.returncode)
