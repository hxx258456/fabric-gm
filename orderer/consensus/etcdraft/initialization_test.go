/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package etcdraft_test

import (
	"testing"

	"github.com/hxx258456/fabric-gm/bccsp/sw"
	"github.com/hxx258456/fabric-gm/common/metrics/disabled"
	"github.com/hxx258456/fabric-gm/internal/pkg/comm"
	"github.com/hxx258456/fabric-gm/orderer/common/cluster"
	"github.com/hxx258456/fabric-gm/orderer/common/localconfig"
	"github.com/hxx258456/fabric-gm/orderer/common/multichannel"
	"github.com/hxx258456/fabric-gm/orderer/consensus/etcdraft"
	"github.com/hxx258456/fabric-gm/orderer/consensus/etcdraft/mocks"
	"github.com/stretchr/testify/assert"
)

func TestNewEtcdRaftConsenter(t *testing.T) {
	srv, err := comm.NewGRPCServer("127.0.0.1:0", comm.ServerConfig{})
	assert.NoError(t, err)
	defer srv.Stop()
	dialer := &cluster.PredicateDialer{}
	cryptoProvider, err := sw.NewDefaultSecurityLevelWithKeystore(sw.NewDummyKeyStore())
	assert.NoError(t, err)
	consenter := etcdraft.New(dialer,
		&localconfig.TopLevel{},
		comm.ServerConfig{
			SecOpts: comm.SecureOptions{
				Certificate: []byte{1, 2, 3},
			},
		}, srv, &multichannel.Registrar{},
		&mocks.InactiveChainRegistry{},
		&disabled.Provider{},
		cryptoProvider,
	)

	// Assert that the certificate from the gRPC server was passed to the consenter
	assert.Equal(t, []byte{1, 2, 3}, consenter.Cert)
	// Assert that all dependencies for the consenter were populated
	assert.NotNil(t, consenter.Communication)
	assert.NotNil(t, consenter.Chains)
	assert.NotNil(t, consenter.ChainSelector)
	assert.NotNil(t, consenter.Dispatcher)
	assert.NotNil(t, consenter.Logger)
}

func TestNewEtcdRaftConsenterNoSystemChannel(t *testing.T) {
	srv, err := comm.NewGRPCServer("127.0.0.1:0", comm.ServerConfig{})
	assert.NoError(t, err)
	defer srv.Stop()
	dialer := &cluster.PredicateDialer{}
	cryptoProvider, err := sw.NewDefaultSecurityLevelWithKeystore(sw.NewDummyKeyStore())
	assert.NoError(t, err)
	consenter := etcdraft.New(
		dialer,
		&localconfig.TopLevel{},
		comm.ServerConfig{
			SecOpts: comm.SecureOptions{
				Certificate: []byte{1, 2, 3},
			},
		}, srv, &multichannel.Registrar{},
		nil, // without a system channel we have InactiveChainRegistry == nil
		&disabled.Provider{},
		cryptoProvider,
	)

	// Assert that the certificate from the gRPC server was passed to the consenter
	assert.Equal(t, []byte{1, 2, 3}, consenter.Cert)
	// Assert that all dependencies for the consenter were populated
	assert.NotNil(t, consenter.Communication)
	assert.NotNil(t, consenter.Chains)
	assert.NotNil(t, consenter.ChainSelector)
	assert.NotNil(t, consenter.Dispatcher)
	assert.NotNil(t, consenter.Logger)
	assert.Nil(t, consenter.InactiveChainRegistry)
}
