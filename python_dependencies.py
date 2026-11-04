"""Locate release dependencies without installing packages or accessing a network."""
import os
from pathlib import Path
import sys


def activate():
    override=os.environ.get('NDR_PYTHON_DEPS')
    path=Path(override) if override else Path(__file__).with_name('python-dependencies.zip')
    if not path.exists():
        raise RuntimeError('Missing pinned Python dependencies; build a release or use tests/run_backend.py')
    resolved=str(path.resolve())
    if resolved not in sys.path:sys.path.insert(0,resolved)
