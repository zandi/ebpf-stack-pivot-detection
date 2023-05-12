#!/usr/bin/bash

#TAG=`git rev-parse --short --verify HEAD`

# make it easier to build the container with an image name
docker build -t stack_pivot_poc:latest .
