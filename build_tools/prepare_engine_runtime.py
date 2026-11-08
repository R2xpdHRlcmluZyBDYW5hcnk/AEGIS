"""Install checksum-pinned, architecture-independent Snort runtime data outside source."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tarfile
import urllib.request


def prepare(manifest_path, work, prefix):
    manifest=json.loads(Path(manifest_path).read_text())
    work,prefix=Path(work).resolve(),Path(prefix).resolve()
    if work.parent!=Path('/var/tmp') or not work.name.startswith('ips-snort3-') or prefix.parent!=Path('/opt/ips-snort3'):
        raise ValueError('Unexpected runtime data destination')
    for name in ('openappid',):
        spec=dict(manifest[name])
        destination=prefix/'share/appid'
        receipt=destination/(name+'-source.json')
        if receipt.exists() and json.loads(receipt.read_text())==spec:
            continue
        archive=work/(name+'.tar.gz')
        if not archive.exists():
            request=urllib.request.Request(spec['url'],headers={'User-Agent':'IPS-engine-build'})
            with urllib.request.urlopen(request,timeout=120) as source,archive.open('wb') as output:
                shutil.copyfileobj(source,output)
        if hashlib.sha256(archive.read_bytes()).hexdigest()!=spec['sha256']:
            raise ValueError('Runtime source checksum differs: '+name)
        destination.mkdir(parents=True,exist_ok=True)
        with tarfile.open(archive) as package:
            package.extractall(destination,filter='data')
        receipt.write_text(json.dumps(spec,indent=2)+'\n')
    print('Pinned OpenAppID installed outside source')
    for name,filename in (('snort','COPYING'),('snort','LICENSE'),('libdaq','COPYING'),('vectorscan','LICENSE')):
        version=manifest[name]['version']
        source_name={'snort':'snort3-','libdaq':'libdaq-','vectorscan':'vectorscan-vectorscan-'}[name]
        source=work/'src'/(source_name+version)/filename
        if source.exists():
            target=prefix/'share/licenses'/name/filename
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(source,target)


if __name__=='__main__':
    prepare(*sys.argv[1:])
