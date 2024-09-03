#!/bin/bash

cd hello-world-html

# Build the Docker image and tag it with the Jenkins build number
docker build -t ebpfztn:${BUILD_ID} .


