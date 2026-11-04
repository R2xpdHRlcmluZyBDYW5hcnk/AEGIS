"""Build only the response adapter and test the existing engine in an ARM64 VM."""
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


def main():
    if os.geteuid()!=0:raise RuntimeError('Run as root in WSL Debian')
    spec=importlib.util.spec_from_file_location('response_vm',ROOT/'build_tools/check_arm64_inline.py')
    vm=importlib.util.module_from_spec(spec);spec.loader.exec_module(vm)
    engine=Path(os.environ.get('SNORT_ENGINE_PREFIX','/opt/ips-snort3/3.12.4.0-session1'))
    before=hashlib.sha256((engine/'bin/snort').read_bytes()).hexdigest()
    os.environ['SNORT_ENGINE_PREFIX']=str(engine)
    with tempfile.TemporaryDirectory(prefix='ips-response-vm-',dir='/var/tmp') as directory:
        vm.WORK=Path(directory)
        library=vm.WORK/'libips-response.so'
        vm.run('aarch64-linux-gnu-gcc','-shared','-fPIC','-O2','-Wall','-Wextra','-Werror',
               '-Wl,-z,relro,-z,now','-o',str(library),str(ROOT/'native_response.c'),'-ldl','-pthread')
        root=vm.prepare()
        for name in ('rule_identity.py',):vm.copy(ROOT/name,root/'project'/name)
        vm.copy(library,root/'opt/libips-response.so')
        script=root/'run-test.sh'
        text=script.read_text();start=text.index('unshare -n python3')
        text=text[:start]+'''modprobe ipv6
export NDR_RESPONSE_LIBRARY=/opt/libips-response.so
unshare -n python3 -B tests/check_snort_native.py --inline
v4=$?
unshare -n python3 -B tests/check_snort_native.py --inline --ipv6
v6=$?
echo RESPONSE_IPV4_RESULT=$v4
echo RESPONSE_IPV6_RESULT=$v6
'''
        script.write_text(text)
        command=['qemu-system-aarch64','-machine','virt','-cpu','max','-smp','4','-m','2048','-nographic','-no-reboot',
            '-kernel',str(root/'boot'/('vmlinuz-'+vm.KERNEL)),'-initrd',str(vm.WORK/'initrd.gz'),
            '-append','console=ttyAMA0 panic=-1','-virtfs','local,path='+str(root)+',mount_tag=rootfs,security_model=none','-nic','none']
        with (vm.WORK/'console.log').open('wb') as log:vm.run(*command,stdout=log,stderr=subprocess.STDOUT,timeout=420)
        result=(vm.WORK/'console.log').read_text(errors='replace');print(result[-18000:])
        if 'RESPONSE_IPV4_RESULT=0' not in result or 'RESPONSE_IPV6_RESULT=0' not in result:
            raise RuntimeError('Native IPv4/IPv6 reject validation failed')
    assert hashlib.sha256((engine/'bin/snort').read_bytes()).hexdigest()==before
    print('Existing Snort binary unchanged; temporary VM and compiled test adapter removed')


if __name__=='__main__':main()
