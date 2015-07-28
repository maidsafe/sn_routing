#!/bin/bash
#
# Create a package for Vault Release binaries

# Stop the script if any command fails
set -e

# Get current version from Cargo.toml
RootDir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
Version=$(sed -n 's/[ \t]*version[ \t]*=[ \t]*"\([^"]*\)".*/\1/p' $RootDir/Cargo.toml)

function create_package {
  fpm \
    -t $1 \
    -s dir \
    -C $RootDir \
    --force \
    --name safe-vault \
    --version $Version \
    --license GPLv3 \
    --vendor MaidSafe \
    --directories /var/cache/safe/ \
    --maintainer "MaidSafeQA <qa@maidsafe.net>" \
    --description "SAFE Network vault" \
    --url "http://maidsafe.net" \
    target/release/safe_vault=/usr/local/bin/ \
    installer/common/safe_vault.bootstrap.cache=/var/cache/safe/
}

cd $RootDir
cargo update
cargo build --release
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
