# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

ARG GO_VER
ARG ALPINE_VER
FROM golang:${GO_VER}-alpine${ALPINE_VER} as golang
RUN sed -i "s?dl-cdn.alpinelinux.org?mirrors.aliyun.com?g" /etc/apk/repositories \
    && apk add --no-cache \
	bash \
	gcc \
	git \
	make \
	musl-dev;

ADD . $GOPATH/src/github.com/hyperledger/fabric
WORKDIR $GOPATH/src/github.com/hyperledger/fabric

FROM golang as tools
RUN go env -w GOPROXY=https://goproxy.cn,direct \
	&& go env -w GOPRIVATE=github.com/hxx258456 \
    && make configtxgen configtxlator cryptogen peer discover idemixgen

FROM golang:${GO_VER}-alpine
RUN go env -w GOPROXY=https://goproxy.cn,direct \
	&& go env -w GOPRIVATE=github.com/hxx258456
# git is required to support `go list -m`
ENV TIME_ZONE=Asia/Shanghai LANG=en_US.UTF-8 LANGUAGE=en_US.UTF-8 LC_ALL=en_US.UTF-8
RUN sed -i "s?dl-cdn.alpinelinux.org?mirrors.aliyun.com?g" /etc/apk/repositories \
    && apk add --no-cache \
	bash \
	git \
	jq \
	tzdata \
	&& echo "${TIME_ZONE}" > /etc/timezone \
	&& ln -sf /usr/share/zoneinfo/${TIME_ZONE} /etc/localtime
ENV FABRIC_CFG_PATH /etc/hyperledger/fabric
VOLUME /etc/hyperledger/fabric
COPY --from=tools /go/src/github.com/hyperledger/fabric/build/bin /usr/local/bin
COPY --from=tools /go/src/github.com/hyperledger/fabric/sampleconfig ${FABRIC_CFG_PATH}
