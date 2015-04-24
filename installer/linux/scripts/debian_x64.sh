#!/bin/bash
#
# Create a debian package for Vault Release binaries
#
# Requires FPM installed > https://github.com/jordansissel/fpm
#
# TODO update -C to pick up correct files when vault completed
#
fpm -s dir -t deb -C ../../target/release/maidsafe_vault --name safe_network_vault --version 0.0.3 --license GPLv3 --vendor MaidSafe --maintainer qa@maidsafe.net --prefix $HOME/MaidSafe --description "The Ants are coming!!" --url "http://maidsafe.net"
