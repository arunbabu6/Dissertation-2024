#!/bin/bash

cd hello-world-html

# Build the Docker image and tag it with the Jenkins build number
docker build --output type=image,push=false --hash -t ebpfztn:${BUILD_ID} .
