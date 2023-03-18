#!/bin/bash
#
# Multi-arch build to get good performance on arm64 (e.g. Docker for Mac), etc. 
#
# You may need to create a new builder first, e.g.:
# docker buildx create my-builder --use
#
docker buildx build -t anrid/ipcheck:latest --push --platform linux/amd64,linux/arm/v7,linux/arm64 .
