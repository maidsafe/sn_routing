#!/bin/bash
#
# Create a package for Vault Release binaries

# Stop the script if any command fails
set -e

# Get current version and executable's name from Cargo.toml
RootDir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
Version=$(sed -n 's/[ \t]*version[ \t]*=[ \t]*"\([^"]*\)".*/\1/p' $RootDir/Cargo.toml)
VaultName=$(sed -n 's/[ \t]*name[ \t]*=[ \t]*"\([^"]*\)".*/\1/p' $RootDir/Cargo.toml)
VaultPath=/usr/local/bin/
ServiceName=safe-vault.service
ServicePath=/usr/lib/systemd/system/

function prepare_scripts {
  mkdir -p systemd

  # This will check the exe and service files are installed and will add and start the service
  AfterInstall=systemd/after_install.sh
  printf '#!/bin/sh\n' > $AfterInstall
  printf 'if [ ! -f %s%s ] ; then\n' $VaultPath $VaultName >> $AfterInstall
  printf '  echo "%s executable is missing from %s" >&2\n' $VaultName $VaultPath >> $AfterInstall
  printf '  exit 1\nfi\n\n' >> $AfterInstall
  printf 'if [ ! -f %s%s ] ; then\n' $ServicePath $ServiceName >> $AfterInstall
  printf '  echo "%s is missing from %s" >&2\n' $ServiceName $ServicePath >> $AfterInstall
  printf '  exit 1\nfi\n\n' >> $AfterInstall
  printf 'systemctl enable %s\n' $ServiceName >> $AfterInstall
  printf 'systemctl start %s\n' $ServiceName >> $AfterInstall

  # This will stop and remove the service
  BeforeRemove=systemd/before_remove.sh
  printf '#!/bin/sh\n' > $BeforeRemove
  printf 'systemctl stop %s\n' $ServiceName >> $BeforeRemove
  printf 'systemctl disable %s\n' $ServiceName >> $BeforeRemove

  # This specifies the service
  Service=systemd/$ServiceName
  printf '[Unit]\nDescription=SAFE Network Vault\n\n[Service]\n' > $Service
  printf 'ExecStart=%s%s\n\n' $VaultPath $VaultName >> $Service
  printf '[Install]\nWantedBy=multi-user.target' >> $Service

  chmod 755 $AfterInstall $BeforeRemove
}

function create_package {
  prepare_scripts

  fpm \
    -t $1 \
    -s dir \
    --force \
    --name safe-vault \
    --version $Version \
    --license GPLv3 \
    --vendor MaidSafe \
    --directories /var/cache/safe/ \
    --maintainer "MaidSafeQA <qa@maidsafe.net>" \
    --description "SAFE Network vault" \
    --url "http://maidsafe.net" \
    --after-install systemd/after_install.sh\
    --before-remove systemd/before_remove.sh \
    $RootDir/target/release/$VaultName=$VaultPath \
    $RootDir/installer/common/$VaultName.bootstrap.cache=/var/cache/safe/ \
    systemd/$ServiceName=$ServicePath
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
