#!/bin/bash

set -ex

CHANNEL=${CHANNEL:-stable}

# Skip if $ONLY_DEPLOY is defined and this is not a deploy (that is, this build
# was not triggered by pushing a tag).
[ -n "$ONLY_DEPLOY" -a -z "$TRAVIS_TAG" ] && exit 0

# Skip if this is a deploy, but rust channel is not stable.
[ -n "$TRAVIS_TAG" -a "$CHANNEL" != stable ] && exit 0

case "$TRAVIS_OS_NAME" in
  linux)
    HOST=x86_64-unknown-linux-gnu
    ;;
  osx)
    HOST=x86_64-apple-darwin
    ;;
esac

# Install libsodium
(curl -sSLO https://github.com/maidsafe/QA/raw/master/Bash%20Scripts/Travis/install_libsodium.sh &&
 chmod a+x install_libsodium.sh &&
 ./install_libsodium.sh)

# Install rust
curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain=$CHANNEL
rustc -V
cargo -V

# Install crates for cross-compilation
if [ -n "$TARGET" -a "$HOST" != "$TARGET" ]; then
  rustup target add $TARGET
fi
