#!/bin/bash

set -ex

CHANNEL=${CHANNEL:-stable}

# Skip if $ONLY_DEPLOY is defined and this is not a deploy (that is, this build
# was not triggered by pushing a version change commit).
[ -n "$ONLY_DEPLOY" -a -z "$TRAVIS_TAG" ] && exit 0

# Skip if this is a deploy, but rust channel is not stable.
[ -n "$TRAVIS_TAG" -a "$CHANNEL" != stable ] && exit 0

export RUST_BACKTRACE=1
ARG_FEATURES=()
ARG_TARGET=()

if [ -n "$FEATURES" ]; then
  ARG_FEATURES+=( --features "$FEATURES" )
fi

if [ -n "$TARGET" ]; then
  ARG_TARGET+=( --target "$TARGET" )
fi

# Build and run tests with all features specified in $FEATURES
cargo build --release "${ARG_FEATURES[@]}" "${ARG_TARGET[@]}"
cargo test --release "${ARG_FEATURES[@]}" "${ARG_TARGET[@]}"

# Also build (but don't run) without any features.
if [ -n "$FEATURES" ]; then
  cargo build --release "${ARG_TARGET[@]}"
  cargo test --release --no-run "${ARG_TARGET[@]}"
fi
