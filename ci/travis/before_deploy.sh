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

cp target/$TARGET/release/$PROJECT_NAME $TMP_DIR
cp installer/common/*.config $TMP_DIR

pushd $TMP_DIR
tar czf $OUT_DIR/${PROJECT_NAME}-${TRAVIS_TAG}-${TARGET}.tar.gz *
popd

rm -r $TMP_DIR
