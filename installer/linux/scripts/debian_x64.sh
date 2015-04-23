#!/bin/bash
#
# Create a debian package for Vault Release binaries
#
fpm -s dir -t deb -C target/release --name maidsafe_vault --version 0.0.3 --iteration 1 --maintainer qa@maidsafe.net --prefix $HOME/MaidSafe --description "The Ants are coming!!";
