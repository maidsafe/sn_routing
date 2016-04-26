#!/bin/bash

set -ex

# This works on both linux and osx
mktempd() {
  echo $(mktemp -d 2>/dev/null || mktemp -d -t tmp)
}

export RUST_BACKTRACE=1
cargo build --target $TARGET --release

TMP_DIR=$(mktempd)
OUT_DIR=$(pwd)

NAME=$PROJECT_NAME-$TRAVIS_TAG-$PLATFORM

mkdir $TMP_DIR/$NAME
cp target/$TARGET/release/$PROJECT_NAME $TMP_DIR/$NAME
cp installer/bundle* $TMP_DIR/$NAME

pushd $TMP_DIR
tar czf $OUT_DIR/$NAME.tar.gz *
popd

rm -r $TMP_DIR
