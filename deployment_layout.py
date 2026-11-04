"""Resolve the separate Snort console installation without touching legacy files."""
import json
from pathlib import Path

MARKER=Path('/etc/ips-snort-deployment.json')


def layout():
    if not MARKER.exists():
        return dict(program_dir='/usr/local/bin',config='/etc/ips-web.conf')
    value=json.loads(MARKER.read_text())
    if value.get('program_dir')!='/opt/ips-console/bin' or value.get('config')!='/etc/ips-snort-web.conf':
        raise ValueError('Unexpected native console deployment layout')
    return value
