"""Install the recorded WSL Debian build prerequisites through apt."""
import os
from pathlib import Path
import subprocess


def main():
    if os.geteuid()!=0 or 'microsoft' not in Path('/proc/sys/kernel/osrelease').read_text().lower():
        raise SystemExit('Run as root inside WSL Debian 13')
    packages=['gcc-aarch64-linux-gnu','g++-aarch64-linux-gnu','cmake','ninja-build','autoconf',
              'automake','libtool','pkg-config','flex','libfl-dev','qemu-user','patchelf',
              'python3','python3-requests','ca-certificates','openssl','libboost-dev','ragel']
    packages += [name+':arm64' for name in ('libdumbnet-dev','libhwloc-dev','libluajit-5.1-dev',
                 'libpcap-dev','libpcre2-dev','libssl-dev','liblzma-dev','zlib1g-dev','libmnl-dev',
                 'libunwind-dev','libnuma-dev','uuid-dev','libbrotli-dev')]
    subprocess.run(['dpkg','--add-architecture','arm64'],check=True)
    subprocess.run(['apt-get','update','-qq'],check=True)
    subprocess.run(['apt-get','install','-y','--no-install-recommends',*packages],check=True)
    # NodeSource's signed node_26.x apt repository must be configured first.
    # Do not download a standalone Node binary or install it in a user profile.
    subprocess.run(['apt-get','install','-y','nodejs=26.13.0-1nodesource1'],check=True)
    if subprocess.check_output(['/usr/bin/node','--version'],text=True).strip()!='v26.13.0':
        raise SystemExit('Unexpected apt Node.js version; review toolchain-sources.json')
    print('WSL cross-build prerequisites and apt Node.js verified')


if __name__=='__main__': main()
