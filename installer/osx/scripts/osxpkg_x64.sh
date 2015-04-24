#!/bin/bash
#
# Create an OSX package for Vault Release binaries
#
# TODO update -C to pick up correct files when vault completed
fpm -s dir -t osxpkg -C ../../target/release --name safe_network_vault --version 0.0.3 --license GPLv3 --vendor MaidSafe --maintainer qa@maidsafe.net --prefix $HOME/MaidSafe --description "The Ants are coming!!" --url "http://maidsafe.net"
