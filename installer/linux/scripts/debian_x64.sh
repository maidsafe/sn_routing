#!/bin/bash
#
# Create a debian package for Vault Release binaries
#
# Requires FPM installed > https://github.com/jordansissel/fpm
#
fpm -s dir -t deb -C ../../../target/release/ --name maidsafe-vault --version 0.1.0 --prefix /opt/maidsafe --description "The Ants are coming!" --url "http://maidsafe.net" --license "GPLv3" --vendor MaidSafe --maintainer "MaidSafe_QA <qa@maidsafe.net>" maidsafe_vault ../../installer/maidsafe_vault.bootstrap.cache
