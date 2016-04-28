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

# Install libsodium
# (curl -sSLO https://github.com/maidsafe/QA/raw/master/Bash%20Scripts/Travis/install_libsodium.sh &&
#  chmod a+x install_libsodium.sh &&
#  ./install_libsodium.sh)
./ci/travis/install_libsodium.sh


# Install rust
curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain=$CHANNEL
rustc -V
cargo -V

# Install crates for cross-compilation
if [ -n "$TARGET" -a "$HOST" != "$TARGET" ]; then
  rustup target add $TARGET
fi

# Configure cargo
case "$TARGET" in
  arm*-gnueabihf)
    PREFIX=arm-linux-gnueabihf-

    # information about the cross compiler
    ${PREFIX}gcc -v

    # tell cargo which linker to use for cross compilation
    mkdir -p .cargo
    echo "[target.$TARGET]" >> .cargo/config
    echo "linker = \"${PREFIX}gcc\"" >> .cargo/config
    ;;
  *)
    ;;
esac
