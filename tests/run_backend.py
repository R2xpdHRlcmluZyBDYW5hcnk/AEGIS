"""Run backend checks for the Go runtime and standard-library deployment tools."""
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


if __name__=='__main__':
    arguments=sys.argv[1:] or ['discover','-s','tests','-q']
    result=subprocess.run([sys.executable,'-B','-m','unittest',*arguments],cwd=ROOT)
    raise SystemExit(result.returncode)
