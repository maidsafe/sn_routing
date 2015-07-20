#!/bin/bash
#
# Create a package for Vault Release binaries

# Get current version from Cargo.toml
RootDir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
Version=$(sed -n 's/[ \t]*version[ \t]*=[ \t]*"\([^"]*\)".*/\1/p' $RootDir/Cargo.toml)

function create_package {
  fpm \
    -t $1 \
    -s dir \
    -C $RootDir \
    --prefix /opt/maidsafe \
    --force \
    --name maidsafe-vault \
    --version $Version \
    --license GPLv3 \
    --vendor MaidSafe \
    --directories /opt/maidsafe/ \
    --maintainer "MaidSafeQA <qa@maidsafe.net>" \
    --description "SAFE Network vault" \
    --url "http://maidsafe.net" \
    --after-install $RootDir/installer/common/scripts/after_install.sh \
    --after-remove $RootDir/installer/common/scripts/after_remove.sh \
    target/release/maidsafe_vault=maidsafe_vault \
    installer/common/maidsafe_vault.bootstrap.cache=maidsafe_vault.bootstrap.cache
}

mkdir -p $RootDir/packages/$1
cd $RootDir/packages/$1
if [[ "$1" == "linux" ]]
then
  create_package deb
  create_package rpm
elif [[ "$1" == "osx" ]]
then
  create_package osxpkg
fi
