#!/usr/bin/env bash
set -e

if [ -z "$IMAGE_NAME" ]; then
  echo "Error: IMAGE_NAME is not set or is empty."
  exit 1
fi

TAG=${TAG-latest}
DOCKER_BUILD=${DOCKER_BUILD-1}
DOCKER_BUILD_PUSH=${DOCKER_BUILD_PUSH-0}

if [ $DOCKER_BUILD -eq 1 ]; then
  docker build $DOCKER_BUILD_OPTIONS -t $IMAGE_NAME:$TAG .
fi
if [ $DOCKER_BUILD_PUSH -eq 1 ]; then
  docker push $IMAGE_NAME:$TAG
fi