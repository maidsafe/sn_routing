#!/bin/bash
#
# Create a Debian or RPM package for Vault Release binaries

# Requires FPM to be installed > https://github.com/jordansissel/fpm
hash fpm 2>/dev/null || {
  echo >&2 "
You need fpm.  Run:
    sudo apt-get install ruby-dev rubygems gcc -y
OR
    sudo yum install ruby-devel rubygems gcc

Then run:
    sudo gem install fpm

";
  exit 1;
}

# Requires rpm-build to be installed
hash rpmbuild 2>/dev/null || {
  echo >&2 "
You need rpm-build.  Run:
    sudo apt-get install rpm -y
OR
    sudo yum install rpm-build

";
  exit 2;
}

Platform=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

"${0%/*}/../../common/scripts/invoke_fpm.sh" ${Platform##*/}
