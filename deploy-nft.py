#!/usr/bin/env python3
"""Deploy only the NFQUEUE ingress rule and its generator without restarting IPS."""
import argparse
import ast
import copy
import datetime
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile

TARGET = Path('/usr/local/bin/ips-supervisor')
BACKUPS = Path('/var/backups/ips-nft')
NFT = '/usr/sbin/nft'
LO_EXPR = [{'match': {'op': '==', 'left': {'meta': {'key': 'iifname'}}, 'right': 'lo'}},
           {'return': None}]


def run(args, text=None):
    try:
        return subprocess.run(args, input=text, text=True, capture_output=True, check=True).stdout
    except subprocess.CalledProcessError as error:
        raise RuntimeError('Command failed: ' + ' '.join(args) + '\n' + error.stderr.strip()) from error


def load_source(source):
    tree = ast.parse(source)
    compile(tree, str(TARGET), 'exec')
    return tree


def validate_source(before, after):
    def remaining(source):
        result = []
        for node in load_source(source).body:
            if isinstance(node, ast.FunctionDef) and node.name == 'nft_rules':
                continue
            result.append(node)
        return ast.dump(ast.Module(body=result, type_ignores=[]), include_attributes=False)
    if remaining(before) != remaining(after):
        raise ValueError('Supervisor has unrelated changes; refusing NFQUEUE-only deployment')


def ingress_rule(table):
    rules = [obj['rule'] for obj in table['nftables'] if 'rule' in obj]
    matches = [rule for rule in rules if rule.get('chain') == 'prerouting'
               and any(expr.get('match', {}).get('left') == {'meta': {'key': 'iifname'}}
                       for expr in rule.get('expr', []))]
    if len(matches) != 1:
        raise ValueError('Expected exactly one ingress-interface rule')
    rule = matches[0]
    if rule['family'] != 'inet' or rule['table'] != 'ips' or rules[0] is not rule:
        raise ValueError('Unexpected ingress-rule location')
    expr = rule['expr']
    if expr != LO_EXPR:
        raise ValueError('Unexpected ingress-interface policy')
    return rule


def replacement(rule, expr):
    updated = {key: rule[key] for key in ('family', 'table', 'chain', 'handle')}
    updated['expr'] = expr
    return json.dumps({'nftables': [{'replace': {'rule': updated}}]})


def stable_table(table, handle):
    """Ignore only packet counters and the one rule intentionally replaced."""
    table = copy.deepcopy(table)
    for obj in table['nftables']:
        rule = obj.get('rule', {})
        if rule.get('handle') == handle and rule.get('chain') == 'prerouting':
            rule['expr'] = []
        for expr in rule.get('expr', []):
            if 'counter' in expr:
                expr['counter'] = {}
    return table


def process_identity(pid):
    fields = (Path('/proc') / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()
    return [int(pid), fields[19]]


def priority_transaction(table, priority):
    """Recreate only the dedicated IPS table in one atomic nft transaction."""
    commands=[{'delete':{'table':{'family':'inet','name':'ips'}}}]
    chains=[]
    for item in table['nftables']:
        if 'metainfo' in item:continue
        if len(item)!=1:raise ValueError('Unexpected IPS object')
        kind,data=next(iter(item.items()));data=copy.deepcopy(data)
        if kind not in ('table','chain','rule') or data.get('family')!='inet':
            raise ValueError('Unsupported IPS table object')
        if (data.get('name') if kind=='table' else data.get('table'))!='ips':
            raise ValueError('Unexpected IPS table')
        data.pop('handle',None)
        if kind=='chain':
            if data.get('name')!='prerouting' or data.get('hook')!='prerouting' or data.get('prio') not in (-150,-90):
                raise ValueError('Unexpected IPS chain')
            chains.append(data);data['prio']=priority
        commands.append({'add':{kind:data}})
    if len(chains)!=1:raise ValueError('Expected one IPS base chain')
    return json.dumps({'nftables':commands})


def policy_signature(table):
    objects=[]
    for item in table['nftables']:
        if 'metainfo' in item:continue
        item=copy.deepcopy(item)
        for kind,data in item.items():
            data.pop('handle',None)
            if kind=='chain':data.pop('prio',None)
            for expr in data.get('expr',[]):
                if 'counter' in expr:expr['counter']={}
        objects.append(item)
    return objects


def processes():
    supervisor = int(run(['systemctl', 'show', 'ips.service', '-p', 'MainPID', '--value']).strip())
    engine = int(Path('/run/snort/snort.pid').read_text().strip())
    if supervisor <= 1 or engine <= 1:
        raise RuntimeError('IPS must already be running')
    return [process_identity(supervisor), process_identity(engine)]


def atomic_write(data, target, mode):
    with tempfile.NamedTemporaryFile(dir=target.parent, prefix='.' + target.name + '-', delete=False) as handle:
        staged = Path(handle.name)
        try:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
            os.chmod(staged, mode)
        except BaseException:
            staged.unlink(missing_ok=True)
            raise
    try:
        os.replace(staged, target)
    finally:
        staged.unlink(missing_ok=True)


def generated_rules(path):
    loader = importlib.machinery.SourceFileLoader('nfqueue_candidate', str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module.nft_rules()


def upgrade(release):
    target=TARGET.resolve()
    if TARGET==Path('/usr/local/bin/ips-supervisor') and not TARGET.exists():
        target=Path('/opt/ips-console/bin/ips-supervisor')
    if TARGET.is_symlink() and target!=Path('/opt/ips-console/bin/ips-supervisor'):
        raise ValueError('Unexpected supervisor symlink target')
    if not target.is_file():
        raise ValueError('Expected a regular installed supervisor file')
    original = target.read_bytes()
    candidate = (release / 'ips-supervisor').read_bytes()
    validate_source(original, candidate)
    before_processes = processes()
    before = json.loads(run([NFT, '-j', 'list', 'table', 'inet', 'ips']))
    rule = ingress_rule(before)
    old_priority=next(obj['chain']['prio'] for obj in before['nftables'] if 'chain' in obj)
    change = priority_transaction(before, -90)
    rollback = priority_transaction(before, old_priority)
    run([NFT, '-c', '-f', '-'], generated_rules(release / 'ips-supervisor'))
    run([NFT, '-c', '-j', '-f', '-'], change)
    backup = BACKUPS / (datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    backup.mkdir(parents=True, mode=0o700)
    os.chmod(BACKUPS, 0o700)
    atomic_write(original, backup / 'ips-supervisor.before', 0o700)
    atomic_write(rollback.encode(), backup / 'rollback-rule.json', 0o600)
    atomic_write(json.dumps(before).encode(), backup / 'table.before.json', 0o600)
    mode = target.stat().st_mode & 0o777
    applied = False
    try:
        atomic_write(candidate, target, mode)
        run([NFT, '-j', '-f', '-'], change)
        applied = True
        after = json.loads(run([NFT, '-j', 'list', 'table', 'inet', 'ips']))
        if ingress_rule(after)['expr'] != LO_EXPR:
            raise RuntimeError('Ingress-rule verification failed')
        if policy_signature(before) != policy_signature(after):
            raise RuntimeError('Unrelated NFQUEUE objects changed')
        if next(obj['chain']['prio'] for obj in after['nftables'] if 'chain' in obj)!=-90:
            raise RuntimeError('NFQUEUE hook priority verification failed')
        if processes() != before_processes:
            raise RuntimeError('IPS process identities changed')
        if target.read_bytes() != candidate:
            raise RuntimeError('Installed generator verification failed')
    except BaseException:
        atomic_write(original, target, mode)
        if applied:
            run([NFT, '-j', '-f', '-'], rollback)
        raise
    print('NFQUEUE ingress: prerouting priority -90, after destination NAT')
    print('Generator installed; supervisor and Snort process identities unchanged.')
    print('Backup: ' + str(backup))
    print('The running supervisor retains its old generator until its next start;')
    print('if the IPS table disappears before then, it may recreate the previous policy.')


def prepare(output):
    root = Path(__file__).resolve().parent
    output = output.resolve()
    if output.is_relative_to(root):
        raise ValueError('Stage NFQUEUE releases outside the source directory')
    output.mkdir(parents=True, exist_ok=True)
    checksums = []
    for name in ('ips-supervisor', 'log_storage.py', 'deploy-nft.py'):
        data = (root / name).read_bytes().removeprefix(b'\xef\xbb\xbf').replace(b'\r\n', b'\n')
        load_source(data)
        (output / name).write_bytes(data)
        checksums.append(hashlib.sha256(data).hexdigest() + '  ' + name + '\n')
    (output / 'SHA256SUMS').write_text(''.join(checksums), encoding='utf-8', newline='\n')
    print('NFQUEUE-only release prepared.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--prepare', type=Path)
    group.add_argument('--release', type=Path)
    args = parser.parse_args()
    if args.prepare:
        prepare(args.prepare)
    else:
        import fcntl
        import sys
        sys.dont_write_bytecode = True
        with open('/run/ips-deploy.lock', 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            upgrade(args.release.resolve())
