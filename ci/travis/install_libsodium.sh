#!/bin/bash

set -ex

# Set the libsodium version if it isn't already set
if [ -z "$LibSodiumVersion" ]; then
  LibSodiumVersion=1.0.9
fi

if [ -n "$LibSodiumHost" ]; then
  HOST="--host=$LibSodiumHost"
fi

# Check to see if libsodium dir has been retrieved from cache
LibSodiumInstallPath=$HOME/libsodium/$LibSodiumVersion
if [ ! -d "$LibSodiumInstallPath/lib" ]; then
  # If not, build and install it
  pushd $HOME
  rm -rf libsodium
  mkdir -p temp
  cd temp
  wget https://github.com/jedisct1/libsodium/releases/download/$LibSodiumVersion/libsodium-$LibSodiumVersion.tar.gz
  tar xfz libsodium-$LibSodiumVersion.tar.gz
  cd libsodium-$LibSodiumVersion
  ./configure $HOST --prefix=$LibSodiumInstallPath --enable-shared=no --disable-pie
  Cores=$((hash nproc 2>/dev/null && nproc) || (hash sysctl 2>/dev/null && sysctl -n hw.ncpu) || echo 1)
  make -j$Cores
  make install
  popd
else
  echo "Using cached libsodium directory (version $LibSodiumVersion)";
fi

export PKG_CONFIG_PATH=$LibSodiumInstallPath/lib/pkgconfig:$PKG_CONFIG_PATH
