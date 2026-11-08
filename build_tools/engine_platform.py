"""Select compatible engine sources, tools and runners for each 64-bit target."""
import argparse
import copy
import json
from pathlib import Path
import platform


def architecture(value):
    aliases={'arm64':'aarch64','aarch64':'aarch64','amd64':'x86_64','x86_64':'x86_64'}
    try:return aliases[value.lower()]
    except KeyError:raise ValueError('Supported engine targets are aarch64 and x86_64') from None


def matcher(arch):
    return 'vectorscan' if architecture(arch)=='aarch64' else 'hyperscan'


def sources_for(sources,arch=None):
    result=copy.deepcopy(sources)
    arch=architecture(arch or result['target']['architecture'])
    result['target']['architecture']=arch
    selected=matcher(arch)
    if selected not in result:raise ValueError('Pinned matching library missing: '+selected)
    result.pop('hyperscan' if selected=='vectorscan' else 'vectorscan',None)
    return result


def elf_architecture(binary):
    with Path(binary).open('rb') as source:header=source.read(20)
    if len(header)!=20 or header[:6]!=b'\x7fELF\x02\x01':
        raise ValueError('Expected a little-endian 64-bit ELF binary')
    arch={183:'aarch64',62:'x86_64'}.get(int.from_bytes(header[18:20],'little'))
    if arch is None:raise ValueError('Unsupported engine ELF architecture')
    return arch


def tool_prefix(arch):
    return 'aarch64-linux-gnu-' if architecture(arch)=='aarch64' else ''


def runner(arch):
    arch=architecture(arch)
    if arch==architecture(platform.machine()):return []
    if arch=='aarch64':return ['qemu-aarch64']
    raise ValueError('Build and validate the x86-64 engine on an x86-64 host')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('sources');parser.add_argument('architecture');parser.add_argument('output')
    args=parser.parse_args()
    sources=sources_for(json.loads(Path(args.sources).read_text()),args.architecture)
    Path(args.output).write_text(json.dumps(sources,indent=2)+'\n')
