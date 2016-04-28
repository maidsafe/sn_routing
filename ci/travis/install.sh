#!/bin/bash

set -ex

CHANNEL=${CHANNEL:-stable}

case "$TRAVIS_OS_NAME" in
  linux)
    HOST=x86_64-unknown-linux-gnu
    ;;
  osx)
    HOST=x86_64-apple-darwin
    ;;
esac

# Install rust
curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain=$CHANNEL
rustc -V
cargo -V

# Install crates for cross-compilation
if [ -n "$TARGET" -a "$HOST" != "$TARGET" ]; then
  rustup target add $TARGET
fi

# Configure toolchain
case "$TARGET" in
  arm*-gnueabihf)
    GCC_PREFIX=arm-linux-gnueabihf-
    ;;
  x86_64-unknown-linux-musl)
    ./ci/travis/install_musl.sh
    GCC_PREFIX=musl-
    ;;
esac

if [ -n "$GCC_PREFIX" ]; then
  # information about the cross compiler
  ${GCC_PREFIX}gcc -v

  # tell cargo which linker to use for cross compilation
  mkdir -p .cargo
  echo "[target.$TARGET]" >> .cargo/config
  echo "linker = \"${GCC_PREFIX}gcc\"" >> .cargo/config
fi

# Install libsodium
./ci/travis/install_libsodium.sh
