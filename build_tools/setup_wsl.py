"""Install the recorded WSL Debian build prerequisites through apt."""
import os
import argparse
from pathlib import Path
import subprocess
from engine_platform import architecture


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--architecture',default='aarch64',choices=('aarch64','arm64','x86_64','amd64'))
    target=architecture(parser.parse_args().architecture)
    if os.geteuid()!=0 or 'microsoft' not in Path('/proc/sys/kernel/osrelease').read_text().lower():
        raise SystemExit('Run as root inside WSL Debian 13')
    packages=['gcc','g++','cmake','ninja-build','autoconf',
              'automake','libtool','pkg-config','flex','libfl-dev','qemu-user','patchelf',
              'python3','python3-requests','ca-certificates','openssl','libboost-dev','ragel']
    if target=='aarch64':packages+=['gcc-aarch64-linux-gnu','g++-aarch64-linux-gnu']
    suffix=':arm64' if target=='aarch64' else ':amd64'
    packages += [name+suffix for name in ('libdumbnet-dev','libhwloc-dev','libluajit-5.1-dev',
                 'libpcap-dev','libpcre2-dev','libssl-dev','liblzma-dev','zlib1g-dev','libmnl-dev',
                 'libunwind-dev','libnuma-dev','uuid-dev','libbrotli-dev')]
    if target=='aarch64':subprocess.run(['dpkg','--add-architecture','arm64'],check=True)
    subprocess.run(['apt-get','update','-qq'],check=True)
    subprocess.run(['apt-get','install','-y','--no-install-recommends',*packages],check=True)
    # NodeSource's signed node_26.x apt repository must be configured first.
    # Do not download a standalone Node binary or install it in a user profile.
    subprocess.run(['apt-get','install','-y','nodejs=26.13.0-1nodesource1'],check=True)
    if subprocess.check_output(['/usr/bin/node','--version'],text=True).strip()!='v26.13.0':
        raise SystemExit('Unexpected apt Node.js version; review toolchain-sources.json')
    print('WSL '+target+' build prerequisites and apt Node.js verified')


if __name__=='__main__': main()
