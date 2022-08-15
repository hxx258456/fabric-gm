/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package comm

import (
	"time"

	"github.com/hxx258456/ccgo/grpc"
	"github.com/hxx258456/fabric-gm/common/crypto/tlsgen"
	"github.com/hxx258456/fabric-gm/common/util"
	"github.com/hxx258456/fabric-gm/internal/pkg/comm"
	"github.com/pkg/errors"
)

const defaultTimeout = time.Second * 5

// Client deals with TLS connections
// to the discovery server
type Client struct {
	TLSCertHash []byte
	*comm.GRPCClient
}

// NewClient creates a new comm client out of the given configuration
func NewClient(conf Config) (*Client, error) {
	if conf.Timeout == time.Duration(0) {
		conf.Timeout = defaultTimeout
	}
	sop, err := conf.ToSecureOptions(newSelfSignedTLSCert)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	cl, err := comm.NewGRPCClient(comm.ClientConfig{
		SecOpts: sop,
		Timeout: conf.Timeout,
	})
	if err != nil {
		return nil, err
	}
	return &Client{GRPCClient: cl, TLSCertHash: util.ComputeSM3(sop.Certificate)}, nil
}

// NewDialer creates a new dialer from the given endpoint
func (c *Client) NewDialer(endpoint string) func() (*grpc.ClientConn, error) {
	return func() (*grpc.ClientConn, error) {
		conn, err := c.NewConnection(endpoint)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		return conn, nil
	}
}

func newSelfSignedTLSCert() (*tlsgen.CertKeyPair, error) {
	ca, err := tlsgen.NewCA()
	if err != nil {
		return nil, err
	}
	return ca.NewClientCertKeyPair()
}
