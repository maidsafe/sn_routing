#!/bin/bash

# Print commands, but do not expand them (to not reveal secure tokens).
set -ev

# This works on both linux and osx
mktempd() {
  echo $(mktemp -d 2>/dev/null || mktemp -d -t tmp)
}

export RUST_BACKTRACE=1
cargo build --target $TARGET --release

# Tag this commit if not already tagged.
git config --global user.name MaidSafe-QA
git config --global user.email qa@maidsafe.net
git fetch --tags

if [ -z $(git tag -l "$PROJECT_VERSION") ]; then
  git tag $PROJECT_VERSION -am "Version $PROJECT_VERSION" $TRAVIS_COMMIT
  git push https://${GH_TOKEN}@github.com/${TRAVIS_REPO_SLUG} tag $PROJECT_VERSION > /dev/null 2>&1
fi

# Create the release archive
NAME="$PROJECT_NAME-v$PROJECT_VERSION-$PLATFORM"

TMP_DIR=$(mktempd)
OUT_DIR=$(pwd)

mkdir $TMP_DIR/$NAME
cp target/$TARGET/release/$PROJECT_NAME $TMP_DIR/$NAME
cp -r installer/bundle/* $TMP_DIR/$NAME

pushd $TMP_DIR
tar czf $OUT_DIR/$NAME.tar.gz *
popd

rm -r $TMP_DIR
