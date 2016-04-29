#! /bin/bash

set -ev

docker login -e="$DOCKER_EMAIL" -u="$DOCKER_USERNAME" -p="$DOCKER_PASSWORD"

BUILD_DIR=installer/docker

cp target/$TARGET/release/$PROJECT_NAME $BUILD_DIR
cp -r installer/bundle/* $BUILD_DIR

pushd $BUILD_DIR
docker build -t $DOCKER_IMAGE:$PROJECT_VERSION .
docker tag $DOCKER_IMAGE:$PROJECT_VERSION $DOCKER_IMAGE:latest
popd

docker push $DOCKER_IMAGE:$PROJECT_VERSION
docker push $DOCKER_IMAGE:latest
