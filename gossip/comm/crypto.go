/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package comm

import (
	"context"

	"github.com/hxx258456/ccgo/grpc/credentials"
	"github.com/hxx258456/ccgo/grpc/peer"
	"github.com/hxx258456/fabric-gm/common/util"
)

func certHashFromRawCert(rawCert []byte) []byte {
	if len(rawCert) == 0 {
		return nil
	}
	return util.ComputeSM3(rawCert)
}

// ExtractCertificateHash extracts the hash of the certificate from the stream
func extractCertificateHashFromContext(ctx context.Context) []byte {
	pr, extracted := peer.FromContext(ctx)
	if !extracted {
		return nil
	}

	authInfo := pr.AuthInfo
	if authInfo == nil {
		return nil
	}

	tlsInfo, isTLSConn := authInfo.(credentials.TLSInfo)
	if !isTLSConn {
		return nil
	}
	certs := tlsInfo.State.PeerCertificates
	if len(certs) == 0 {
		return nil
	}
	raw := certs[0].Raw
	return certHashFromRawCert(raw)
}
