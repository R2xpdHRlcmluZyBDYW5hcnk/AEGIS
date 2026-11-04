"""Persistent console edits isolated from files consumed by the detection engine."""
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
from rule_identity import group_policy_path

CONTROLS = ('LOCAL_RULES', 'HUNT_RULES', 'BAN_RULES', 'BAN_STORE', 'BAN_DETECTOR', 'THRESHOLD_CONF', 'SUPPRESS_LUA',
            'DISABLE_CONF', 'DROP_CONF', 'MODIFY_CONF', 'ACTION_CONF')


def atomic_copy(source, target):
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    staged = target.with_name(target.name + '.draft-new')
    try:
        shutil.copy2(source, staged)
        with open(staged, 'r+b') as handle:
            os.fsync(handle.fileno())
        os.replace(staged, target)
    finally:
        staged.unlink(missing_ok=True)


class DeferredActions:
    def __init__(self, jobs):
        self.jobs = jobs

    def __getattr__(self, name):
        return getattr(self.jobs, name)

    def reload_rules(self):
        return dict(ok=True, pending=True)

    def update_rules(self, *args, **kwargs):
        return dict(ok=False, error='请点击“应用更改”提交待应用配置')


class RuleDrafts:
    def __init__(self, live, state):
        self.live, self.state = live, Path(state).resolve()
        self.root = self.state / 'pending'
        self.data = self.root / 'data'
        self.sources = self.data / 'update/sources'
        self.status = self.root / 'state.json'
        self.dirty = False
        if self.status.exists():
            value = json.loads(self.status.read_text())
            if type(value.get('dirty')) is not bool:
                raise ValueError('Invalid pending rule state')
            self.dirty = value['dirty']
            if not self.dirty:
                self.reset()
        else:
            self.reset()
        name = 'ips_pending_' + str(id(self))
        loader = importlib.machinery.SourceFileLoader(name, live.__file__)
        spec = importlib.util.spec_from_loader(name, loader)
        self.module = importlib.util.module_from_spec(spec)
        # No event ingestion or Web startup occurs when this module is imported.
        loader.exec_module(self.module)
        for key in ('RULES_FILE', 'RULE_UPDATER', 'SNORT_CONF', 'UPDATE_CONF', 'UPDATE_CACHE_DIR',
                    'DIST_RULES_DIR', 'ENGINE_SOCKET', 'NFT'):
            setattr(self.module, key, getattr(live, key))
        for key in CONTROLS:
            setattr(self.module, key, str(self.control_path(key)))
        self.module.SOURCES_DIR = str(self.sources)
        target=group_policy_path(self.module.THRESHOLD_CONF)
        if not target.exists():
            source=group_policy_path(live.THRESHOLD_CONF)
            if source.exists():atomic_copy(source,target)
            else:target.write_text('[]\n',encoding='utf-8')
        original = live.SysInfo.run

        def source_command(command, timeout=8):
            if command[0] == live.RULE_UPDATER:
                command = [*command[:2], '--data-dir', str(self.data), *command[2:]]
            return original(command, timeout=timeout)
        self.module.SysInfo.run = staticmethod(source_command)

    def control_path(self, key):
        return self.root / key / Path(getattr(self.live, key)).name

    def persist(self):
        staged = self.status.with_suffix('.new')
        try:
            with open(staged, 'w', encoding='utf-8') as handle:
                os.chmod(staged, 0o600)
                json.dump(dict(dirty=self.dirty), handle)
                handle.flush(); os.fsync(handle.fileno())
            os.replace(staged, self.status)
        finally:
            staged.unlink(missing_ok=True)

    def reset(self):
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        for key in CONTROLS:
            source, target = Path(getattr(self.live, key)), self.control_path(key)
            target.parent.mkdir(parents=True, exist_ok=True)
            if source.exists():
                atomic_copy(source, target)
            else:
                target.write_text('[]' if key == 'BAN_STORE' else '', encoding='utf-8')
        source=group_policy_path(self.live.THRESHOLD_CONF)
        target=group_policy_path(self.control_path('THRESHOLD_CONF'))
        if source.exists():atomic_copy(source,target)
        else:target.write_text('[]\n',encoding='utf-8')
        if self.sources.exists():
            for path in self.sources.rglob('*'):
                if path.is_file():
                    path.unlink()
        self.sources.mkdir(parents=True, exist_ok=True)
        if Path(self.live.SOURCES_DIR).exists():
            shutil.copytree(self.live.SOURCES_DIR, self.sources, dirs_exist_ok=True)
        self.refresh_catalog()
        self.dirty = False
        self.persist()
        if hasattr(self, 'app'):
            self.app._sources_cache = None
            self.app._rules_index_cache = None

    def refresh_catalog(self):
        index = Path(self.live.UPDATE_CACHE_DIR) / 'index.yaml'
        if index.exists():
            atomic_copy(index, self.data / 'update/cache/index.yaml')

    def signature(self):
        paths = [self.control_path(key) for key in CONTROLS]
        paths.append(group_policy_path(self.control_path('THRESHOLD_CONF')))
        paths += [p for p in self.sources.rglob('*') if p.is_file()]
        return {p.relative_to(self.root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in paths if p.is_file()}

    def sources_changed(self):
        def files(root):
            return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob('*') if p.is_file()} if root.exists() else {}
        return files(self.sources) != files(Path(self.live.SOURCES_DIR))

    def promote(self):
        for key in CONTROLS:
            atomic_copy(self.control_path(key), getattr(self.live, key))
        atomic_copy(group_policy_path(self.control_path('THRESHOLD_CONF')),group_policy_path(self.live.THRESHOLD_CONF))
        target = Path(self.live.SOURCES_DIR)
        target.mkdir(parents=True, exist_ok=True)
        names = {p.relative_to(self.sources) for p in self.sources.rglob('*') if p.is_file()}
        for path in target.rglob('*'):
            if path.is_file() and path.relative_to(target) not in names:
                path.unlink()
        for name in names:
            atomic_copy(self.sources / name, target / name)

    def mutate(self, jobs, method, path, body):
        """An edit never calls the engine, updater application or active-file writers."""
        app = self.app
        before = self.signature()
        with tempfile.TemporaryDirectory(prefix='pending-edit-', dir=self.state) as directory:
            saved = Path(directory) / 'snapshot'
            shutil.copytree(self.root, saved)
            original = app.sys
            app.sys = DeferredActions(jobs)
            try:
                if path == '/api/rules/batch-delete':
                    from ips_control import valid_mutation
                    paths = body.get('paths')
                    if not isinstance(paths, list) or not paths or any(not valid_mutation('DELETE', p) for p in paths):
                        raise ValueError('Invalid batch deletion')
                    suppress_prefix = '/api/rules/suppress/'
                    from urllib.parse import unquote
                    sids = [unquote(p[len(suppress_prefix):]) for p in paths if p.startswith(suppress_prefix)]
                    if sids:
                        self.module.suppress_remove_many(sids, required=True)
                    for item in paths:
                        if item.startswith(suppress_prefix):
                            continue
                        result = self.module.rule_write(app, 'DELETE', item, {})
                        if result.get('ok') is False:
                            raise ValueError(result.get('message', '删除失败'))
                    result = dict(ok=True)
                else:
                    result = self.module.rule_write(app, method, path, body)
                if self.signature() != before:
                    self.dirty = True
                    self.persist()
                if self.dirty:
                    result.update(pending=True)
                if result.get('ok'):
                    result['message'] = '已保存，点击“应用更改”生效'
                return result
            except Exception:
                for item in self.root.rglob('*'):
                    if item.is_file() and not (saved / item.relative_to(self.root)).exists():
                        item.unlink()
                shutil.copytree(saved, self.root, dirs_exist_ok=True)
                self.dirty = json.loads(self.status.read_text())['dirty']
                raise
            finally:
                app.sys = original
