#!/bin/bash
#
# Create a Debian or RPM package for Vault Release binaries

# Requires FPM to be installed > https://github.com/jordansissel/fpm
hash fpm 2>/dev/null || {
  echo >&2 "
You need fpm.  Run:
    sudo apt-get install ruby-dev gcc
OR
    sudo yum install ruby-devel gcc

Then run:
    sudo gem install fpm

";
  exit 1;
}

# Requires rpm-build to be installed
hash rpmbuild 2>/dev/null || {
  echo >&2 "
You need rpm-build.  Run:
    sudo apt-get install rpm
OR
    sudo yum install rpm-build

";
  exit 2;
}

# Get current version from Cargo.toml
RootDir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
Version=$(sed -n 's/[ \t]*version[ \t]*=[ \t]*"\([^"]*\)".*/\1/p' $RootDir/Cargo.toml)

function create_package {
  fpm \
    -t $1 \
    -s dir \
    -C $RootDir/target/release/ \
    --prefix /opt/maidsafe \
    --force \
    --name maidsafe-vault \
    --version $Version \
    --license GPLv3 \
    --vendor MaidSafe \
    --maintainer "MaidSafeQA <qa@maidsafe.net>" \
    --description "SAFE Network vault" \
    --url "http://maidsafe.net" \
    maidsafe_vault \
    ../../installer/maidsafe_vault.bootstrap.cache=maidsafe_vault.bootstrap.cache
}

mkdir -p $RootDir/packages/linux
cd $RootDir/packages/linux
create_package deb
create_package rpm
