#!/usr/bin/bash

#TAG=`git rev-parse --short --verify HEAD`

# make it easier to build the container with an image name
docker build -t stack_pivot_poc:latest .

# update localhost registry tag to push to cluster-internal docker registry
# via forwarded port (forwarded via kubectl port-forward. See `helm status` of docker-registry deployment)
#docker tag stack_pivot_poc:latest localhost:8080/stack_pivot_poc:latest
