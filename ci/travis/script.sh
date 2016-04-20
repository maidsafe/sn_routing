#!/bin/bash

set -ex

CHANNEL=${CHANNEL:-stable}

# Skip if $ONLY_DEPLOY is defined and this is not a deploy (that is, this build
# was not triggered by pushing a tag).
[ -n "$ONLY_DEPLOY" -a -z "$TRAVIS_TAG" ] && exit 0

# Skip if this is a deploy, but rust channel is not stable.
[ -n "$TRAVIS_TAG" -a "$CHANNEL" != stable ] && exit 0

export RUST_BACKTRACE=1
ARGS=()

if [ -n "$FEATURES" ]; then
  ARGS+=( --features "$FEATURES" )
fi

# Build and run tests with all features specified in $FEATURES
cargo build --target "$TARGET" --release "${ARGS[@]}"
cargo test --target "$TARGET" --release "${ARGS[@]}"

# Also build (but don't run) without any features.
if [ -n "$FEATURES" ]; then
  cargo build --target "$TARGET" --release
  cargo test --target "$TARGET" --release --no-run
fi
