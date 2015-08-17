#!/bin/bash
#
# Create an OS X package for Vault Release binaries

# Requires FPM to be installed > https://github.com/jordansissel/fpm
hash fpm 2>/dev/null || {
  echo >&2 "
You need fpm.  Run:
    sudo gem install fpm

";
  exit 1;
}

# Requires gnu-tar to be installed
hash gtar 2>/dev/null || hash gnutar 2>/dev/null || {
  hash brew 2>/dev/null
  if [ $? -eq 0 ]
  then
    echo >&2 "
You need gnu-tar.  Run:
    brew install gnu-tar

";
  else
    echo >&2 '
You need gnu-tar.  This is best installed via brew.  Run:
    ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
    brew install gnu-tar

';
  fi
  exit 2;
}

Platform=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

"${0%/*}/../../common/scripts/invoke_fpm.sh" ${Platform##*/}
