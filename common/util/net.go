/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"context"

	"github.com/hxx258456/ccgo/grpc/peer"
)

func ExtractRemoteAddress(ctx context.Context) string {
	var remoteAddress string
	p, ok := peer.FromContext(ctx)
	if !ok {
		return ""
	}
	if address := p.Addr; address != nil {
		remoteAddress = address.String()
	}
	return remoteAddress
}
