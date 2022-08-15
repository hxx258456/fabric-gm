#!/bin/bash
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

make docker

docker login --username "${DOCKER_USERNAME}" --password "${DOCKER_PASSWORD}"
for image in baseos peer orderer ccenv tools; do
  # RELEASE似乎并未定义?
  for release in ${RELEASE} ${TWO_DIGIT_RELEASE}; do
    docker tag " gcbaas-gm/fabric-${image}" " gcbaas-gm/fabric-${image}:amd64-${release}"
    docker tag " gcbaas-gm/fabric-${image}" " gcbaas-gm/fabric-${image}:${release}"
    docker push " gcbaas-gm/fabric-${image}:amd64-${release}"
    docker push " gcbaas-gm/fabric-${image}:${release}"
  done
done
