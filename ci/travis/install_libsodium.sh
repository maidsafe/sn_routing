#!/bin/bash

set -ex

# Set the libsodium version if it isn't already set
if [ -z "$LibSodiumVersion" ]; then
  LibSodiumVersion="1.0.9"
fi

case $TARGET in
  arm*-gnueabihf)
    HOST="--host=arm-linux-gnueabihf"
    ;;
  i686-*linux-gnu)
    export CFLAGS=-m32
    ;;
  x86_64-unknown-linux-musl)
    HOST="--host=x86_64-linux-musl"
    export CC=musl-gcc
    ;;
esac

# Check to see if libsodium dir has been retrieved from cache
LibSodiumInstallPath=$HOME/libsodium/$LibSodiumVersion/$TARGET
if [ ! -d "$LibSodiumInstallPath/lib" ]; then
  # If not, build and install it
  pushd $HOME
  rm -rf $LibSodiumInstallPath
  mkdir -p libsodium-build
  cd libsodium-build
  wget https://github.com/jedisct1/libsodium/releases/download/$LibSodiumVersion/libsodium-$LibSodiumVersion.tar.gz
  tar xfz libsodium-$LibSodiumVersion.tar.gz
  cd libsodium-$LibSodiumVersion
  ./configure $HOST --prefix=$LibSodiumInstallPath --enable-shared=no --disable-pie
  Cores=$((hash nproc 2>/dev/null && nproc) || (hash sysctl 2>/dev/null && sysctl -n hw.ncpu) || echo 1)
  make -j$Cores
  make install
  popd

  rm -rf $HOME/libsodium-build
else
  echo "Using cached libsodium directory (version $LibSodiumVersion)";
fi
