#! /bin/bash

IMAGE=msafe/vault
TARGET_HOST=$1

if [ -z "$TARGET_HOST" ]; then
  echo "Usage: deploy.sh DOCKER_MACHINE_NAME"
  exit
fi

docker save msafe/vault | bzip2 | pv | \
  docker $(docker-machine config $TARGET_HOST) load
