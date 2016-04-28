#!/bin/bash

# TODO: remove this script once
# https://github.com/travis-ci/apt-package-whitelist/issues/369 is resolved

set -ex

# Check to see if musl is in the cache
if [ ! -f "$HOME/musl/bin/musl-gcc" ]; then
  git clone git://git.musl-libc.org/musl musl-src
  pushd musl-src
  ./configure --prefix=$HOME/musl
  make
  make install
  popd

  rm -rf musl-src
fi
