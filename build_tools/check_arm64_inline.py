"""Run the existing engine in a disposable ARM64 kernel; no router is contacted."""
import argparse
import gzip
import lzma
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
WORK=Path(os.environ.get('SNORT_INLINE_WORK','/var/tmp/ips-snort3-vm'))
KERNEL='6.12.115+deb13-arm64'


def run(*args,**kwargs):
    return subprocess.run(args,check=True,**kwargs)


def copy(source,target):
    source,target=Path(source),Path(target)
    target.parent.mkdir(parents=True,exist_ok=True)
    if source.is_symlink():
        if target.is_symlink() or target.is_file(): target.unlink()
        target.symlink_to(source.readlink())
    elif source.is_dir():
        target.mkdir(parents=True,exist_ok=True)
        for entry in source.iterdir(): copy(entry,target/entry.name)
    else: shutil.copy2(source,target)


def prepare(test='native',ipv6=False):
    if os.geteuid()!=0:
        raise RuntimeError('Run from WSL Debian as root')
    root=WORK/'root';init=WORK/'initramfs';downloads=WORK/'downloads'
    downloads.mkdir(parents=True,exist_ok=True)
    packages=('linux-image-'+KERNEL+':arm64','busybox-static:arm64',
            'python3.13-minimal:arm64','libpython3.13-minimal:arm64','libpython3.13-stdlib:arm64',
            'nftables:arm64','libnftables1:arm64','libnftnl11:arm64','libjansson4:arm64',
            'iproute2:arm64','libelf1t64:arm64','libbpf1:arm64','libcap2:arm64',
            'libtirpc3t64:arm64','libnsl2:arm64','libexpat1:arm64','libbz2-1.0:arm64',
            'libffi8:arm64','libreadline8t64:arm64','libtinfo6:arm64','libselinux1:arm64','libedit2:arm64',
            'libxtables12:arm64','libgmp10:arm64','libbsd0:arm64','libmd0:arm64')
    missing=[name for name in packages if not list(downloads.glob(name.split(':')[0]+'_*.deb'))]
    if missing: run('apt-get','download',*missing,cwd=downloads)
    for name in ('lib','bin','sbin'):
        (root/'usr'/name).mkdir(parents=True,exist_ok=True)
        link=root/name
        if not link.is_symlink(): link.symlink_to('usr/'+name)
    for package in downloads.glob('*.deb'):
        run('dpkg-deb','-x',str(package),str(root))
    for module in (root/'usr/lib/modules'/KERNEL).rglob('*.ko.xz'):
        module.with_suffix('').write_bytes(lzma.decompress(module.read_bytes()))
        module.unlink()
    copy('/usr/lib/aarch64-linux-gnu',root/'usr/lib/aarch64-linux-gnu')
    loader=root/'usr/lib/ld-linux-aarch64.so.1'
    if not loader.exists(): loader.symlink_to('aarch64-linux-gnu/ld-linux-aarch64.so.1')
    # Keep the project copy and runtime outside the source tree.
    for name in ('snort.lua','home-net.lua','suppress.lua','deployment_support.py','deploy-nft.py'):
        copy(ROOT/name,root/'project'/name)
    from build_tools.go_backend import run as go
    go([],root/'project/ips-supervisor')
    for name in ('check_snort_native.py','snort_pcap.py','check_nfq_nat.py'):
        copy(ROOT/'tests'/name,root/'project/tests'/name)
    copy(ROOT/'build_tools/engine_platform.py',root/'project/build_tools/engine_platform.py')
    copy(os.environ.get('SNORT_ENGINE_PREFIX','/opt/ips-snort3/3.12.4.0'),root/'opt/ips-snort3/3.12.4.0')
    for name in ('sh','mount','modprobe','unshare','poweroff','mkdir'):
        path=root/'usr/bin'/name
        if not path.exists(): path.symlink_to('busybox')
    python=root/'usr/bin/python3'
    if not python.exists(): python.symlink_to('python3.13')
    for directory in ('proc','sys','dev','tmp','run','newroot'):
        (root/directory).mkdir(exist_ok=True)
    run('depmod','-b',str(root),KERNEL,stdout=subprocess.DEVNULL)
    init.mkdir(parents=True,exist_ok=True)
    copy(root/'usr/bin/busybox',init/'bin/busybox')
    (init/'bin/sh').symlink_to('busybox') if not (init/'bin/sh').exists() else None
    for directory in ('proc','sys','dev','newroot'):
        (init/directory).mkdir(exist_ok=True)
    for module in ('9p','9pnet_virtio','virtio_pci'):
        dependencies=subprocess.check_output(['modprobe','-d',str(root),'-S',KERNEL,'--show-depends',module],text=True)
        for line in dependencies.splitlines():
            if line.startswith('insmod '):
                path=Path(line.split()[1]);copy(path,init/path.relative_to(root))
    run('depmod','-b',str(init),KERNEL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    script='''#!/bin/sh
BB=/bin/busybox
$BB mount -t proc proc /proc
$BB mount -t sysfs sysfs /sys
$BB mount -t devtmpfs devtmpfs /dev
$BB modprobe 9pnet_virtio
$BB modprobe 9p
$BB mount -t 9p -o trans=virtio,version=9p2000.L,msize=1048576 rootfs /newroot || $BB poweroff -f
for directory in proc sys dev; do $BB mount --move /$directory /newroot/$directory; done
$BB chroot /newroot /bin/sh /run-test.sh
$BB poweroff -f
'''
    (init/'init').write_text(script);(init/'init').chmod(0o755)
    (root/'run-test.sh').write_text('''#!/bin/sh
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
modprobe crc32c_generic
modprobe libcrc32c
modprobe nf_tables
modprobe nft_queue
modprobe nfnetlink_queue
modprobe nft_nat
modprobe nft_masq
modprobe nft_fib_inet
mkdir -p /var/run/netns
touch /run/ndr-isolated-vm
cd /project
unshare -n python3 -B tests/check_snort_native.py --inline
result=$?
echo ARM64_INLINE_RESULT=$result
busybox dmesg | busybox tail -n 12
''')
    if test!='native':
        path=root/'run-test.sh'
        command={'nat':'tests/check_nfq_nat.py',
                 'suppressed':'tests/check_snort_native.py --inline --suppressed-blocks'}[test]
        path.write_text(path.read_text().replace('tests/check_snort_native.py --inline',command))
    path=root/'run-test.sh'
    if ipv6:
        path.write_text(path.read_text().replace('tests/check_snort_native.py --inline',
            'tests/check_snort_native.py --inline --ipv6'))
    adapter=os.environ.get('NDR_RESPONSE_LIBRARY')
    if adapter:
        target=Path('/opt/ips-native-response/1/libips-response.so')
        copy(adapter,root/target.relative_to('/'))
        path.write_text(path.read_text().replace('cd /project\n',
            'export NDR_RESPONSE_LIBRARY='+str(target)+'\ncd /project\n'))
    names=subprocess.check_output(['find','.','-print0'],cwd=init)
    archive=subprocess.run(['cpio','--null','-o','--format=newc'],input=names,cwd=init,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,check=True).stdout
    (WORK/'initrd.gz').write_bytes(gzip.compress(archive,compresslevel=1))
    return root


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    tests=parser.add_mutually_exclusive_group()
    tests.add_argument('--nat',action='store_true')
    tests.add_argument('--suppressed-blocks',action='store_true')
    parser.add_argument('--ipv6',action='store_true')
    args=parser.parse_args()
    if args.ipv6 and args.nat:parser.error('--ipv6 applies to the native inline tests')
    if WORK.parent!=Path('/var/tmp') or not WORK.name.startswith('ips-snort3-vm'):
        raise ValueError('Unexpected VM workspace')
    root=prepare('nat' if args.nat else 'suppressed' if args.suppressed_blocks else 'native',args.ipv6)
    command=['qemu-system-aarch64','-machine','virt','-cpu','max','-smp','4','-m','2048','-nographic','-no-reboot',
             '-kernel',str(root/'boot'/('vmlinuz-'+KERNEL)),'-initrd',str(WORK/'initrd.gz'),
             '-append','console=ttyAMA0 panic=-1','-virtfs','local,path='+str(root)+',mount_tag=rootfs,security_model=none',
             '-nic','none']
    with (WORK/'console.log').open('wb') as log:
        run(*command,stdout=log,stderr=subprocess.STDOUT,timeout=420)
    result=(WORK/'console.log').read_text(errors='replace')
    print(result[result.find('Run /init as init process'):][-14000:])
    if 'ARM64_INLINE_RESULT=0' not in result:
        raise RuntimeError('ARM64 VM inline verification failed')


if __name__=='__main__': main()
