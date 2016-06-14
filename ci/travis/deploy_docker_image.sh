#! /bin/bash

set -ev

docker login -e="$DOCKER_EMAIL" -u="$DOCKER_USERNAME" -p="$DOCKER_PASSWORD"

BUILD_DIR=installer/docker
CRUST_CONFIG=$BUILD_DIR/$PROJECT_NAME.crust.config

cp target/$TARGET/release/$PROJECT_NAME $BUILD_DIR
cp -r $HOME/config/safe_vault/* $BUILD_DIR

# Define listening ports:
cat $CRUST_CONFIG \
  | sed 's/\("tcp_acceptor_port":\).*\([,$]\)/\1 5000\2/' \
  | sed 's/\("utp_acceptor_port":\).*\([,$]\)/\1 5000\2/' \
  | sed 's/\("service_discovery_port":\).*\([,$]\)/\1 5100\2/' \
  > $CRUST_CONFIG.new

mv -f $CRUST_CONFIG.new $CRUST_CONFIG

pushd $BUILD_DIR
docker build -t $DOCKER_IMAGE:$PROJECT_VERSION .
docker tag $DOCKER_IMAGE:$PROJECT_VERSION $DOCKER_IMAGE:latest
popd

docker push $DOCKER_IMAGE:$PROJECT_VERSION
docker push $DOCKER_IMAGE:latest
