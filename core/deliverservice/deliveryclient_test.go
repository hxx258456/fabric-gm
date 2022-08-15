/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package deliverservice

import (
	"fmt"
	"testing"
	"time"

	"github.com/hxx258456/fabric-gm/core/deliverservice/fake"
	"github.com/hxx258456/fabric-gm/internal/pkg/comm"
	"github.com/hxx258456/fabric-gm/internal/pkg/peer/blocksprovider"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:generate counterfeiter -o fake/ledger_info.go --fake-name LedgerInfo . ledgerInfo
type ledgerInfo interface {
	blocksprovider.LedgerInfo
}

func TestStartDeliverForChannel(t *testing.T) {
	fakeLedgerInfo := &fake.LedgerInfo{}
	fakeLedgerInfo.LedgerHeightReturns(0, fmt.Errorf("fake-ledger-error"))

	grpcClient, err := comm.NewGRPCClient(comm.ClientConfig{
		SecOpts: comm.SecureOptions{
			UseTLS:            true,
			RequireClientCert: true,
			// The below certificates were taken from the peer TLS
			// dir as output by cryptogen.
			// They are server.crt and server.key respectively.
			Certificate: []byte(`-----BEGIN CERTIFICATE-----
MIIChTCCAiygAwIBAgIQOrr7/tDzKhhCba04E6QVWzAKBggqhkjOPQQDAjB2MQsw
CQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZy
YW5jaXNjbzEZMBcGA1UEChMQb3JnMS5leGFtcGxlLmNvbTEfMB0GA1UEAxMWdGxz
Y2Eub3JnMS5leGFtcGxlLmNvbTAeFw0xOTA4MjcyMDA2MDBaFw0yOTA4MjQyMDA2
MDBaMFsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQH
Ew1TYW4gRnJhbmNpc2NvMR8wHQYDVQQDExZwZWVyMC5vcmcxLmV4YW1wbGUuY29t
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExglppLxiAYSasrdFsrZJDxRULGBb
wHlArrap9SmAzGIeeIuqe9t3F23Q5Jry9lAnIh8h3UlkvZZpClXcjRiCeqOBtjCB
szAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMC
MAwGA1UdEwEB/wQCMAAwKwYDVR0jBCQwIoAgL35aqafj6SNnWdI4aMLh+oaFJvsA
aoHgYMkcPvvkiWcwRwYDVR0RBEAwPoIWcGVlcjAub3JnMS5leGFtcGxlLmNvbYIF
cGVlcjCCFnBlZXIwLm9yZzEuZXhhbXBsZS5jb22CBXBlZXIwMAoGCCqGSM49BAMC
A0cAMEQCIAiAGoYeKPMd3bqtixZji8q2zGzLmIzq83xdTJoZqm50AiAKleso2EVi
2TwsekWGpMaCOI6JV1+ZONyti6vBChhUYg==
-----END CERTIFICATE-----`),
			Key: []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgxiyAFyD0Eg1NxjbS
U2EKDLoTQr3WPK8z7WyeOSzr+GGhRANCAATGCWmkvGIBhJqyt0WytkkPFFQsYFvA
eUCutqn1KYDMYh54i6p723cXbdDkmvL2UCciHyHdSWS9lmkKVdyNGIJ6
-----END PRIVATE KEY-----`,
			),
		},
	})
	require.NoError(t, err)

	t.Run("Green Path With Mutual TLS", func(t *testing.T) {
		ds := NewDeliverService(&Config{
			DeliverGRPCClient:    grpcClient,
			DeliverServiceConfig: &DeliverServiceConfig{},
		}).(*deliverServiceImpl)

		finalized := make(chan struct{})
		err := ds.StartDeliverForChannel("channel-id", fakeLedgerInfo, func() {
			close(finalized)
		})
		require.NoError(t, err)

		select {
		case <-finalized:
		case <-time.After(time.Second):
			assert.FailNow(t, "finalizer should have executed")
		}

		bp, ok := ds.blockProviders["channel-id"]
		require.True(t, ok, "map entry must exist")
		assert.Equal(t, "76f7a03f8dfdb0ef7c4b28b3901fe163c730e906c70e4cdf887054ad5f608bed", fmt.Sprintf("%x", bp.TLSCertHash))
	})

	t.Run("Green Path without mutual TLS", func(t *testing.T) {
		grpcClient, err := comm.NewGRPCClient(comm.ClientConfig{
			SecOpts: comm.SecureOptions{
				UseTLS: true,
			},
		})
		require.NoError(t, err)

		ds := NewDeliverService(&Config{
			DeliverGRPCClient:    grpcClient,
			DeliverServiceConfig: &DeliverServiceConfig{},
		}).(*deliverServiceImpl)

		finalized := make(chan struct{})
		err = ds.StartDeliverForChannel("channel-id", fakeLedgerInfo, func() {
			close(finalized)
		})
		require.NoError(t, err)

		select {
		case <-finalized:
		case <-time.After(time.Second):
			assert.FailNow(t, "finalizer should have executed")
		}

		bp, ok := ds.blockProviders["channel-id"]
		require.True(t, ok, "map entry must exist")
		assert.Nil(t, bp.TLSCertHash)
	})

	t.Run("Exists", func(t *testing.T) {
		ds := NewDeliverService(&Config{
			DeliverGRPCClient:    grpcClient,
			DeliverServiceConfig: &DeliverServiceConfig{},
		}).(*deliverServiceImpl)

		err = ds.StartDeliverForChannel("channel-id", fakeLedgerInfo, func() {})
		require.NoError(t, err)

		err = ds.StartDeliverForChannel("channel-id", fakeLedgerInfo, func() {})
		assert.EqualError(t, err, "Delivery service - block provider already exists for channel-id found, can't start delivery")
	})

	t.Run("Stopping", func(t *testing.T) {
		ds := NewDeliverService(&Config{
			DeliverGRPCClient:    grpcClient,
			DeliverServiceConfig: &DeliverServiceConfig{},
		}).(*deliverServiceImpl)

		ds.Stop()

		err = ds.StartDeliverForChannel("channel-id", fakeLedgerInfo, func() {})
		assert.EqualError(t, err, "Delivery service is stopping cannot join a new channel channel-id")
	})
}

func TestStopDeliverForChannel(t *testing.T) {
	t.Run("Green path", func(t *testing.T) {
		ds := NewDeliverService(&Config{}).(*deliverServiceImpl)
		doneA := make(chan struct{})
		ds.blockProviders = map[string]*blocksprovider.Deliverer{
			"a": {
				DoneC: doneA,
			},
			"b": {
				DoneC: make(chan struct{}),
			},
		}
		err := ds.StopDeliverForChannel("a")
		assert.NoError(t, err)
		assert.Len(t, ds.blockProviders, 1)
		_, ok := ds.blockProviders["a"]
		assert.False(t, ok)
		select {
		case <-doneA:
		default:
			assert.Fail(t, "should have stopped the blocksprovider")
		}
	})

	t.Run("Already stopping", func(t *testing.T) {
		ds := NewDeliverService(&Config{}).(*deliverServiceImpl)
		ds.blockProviders = map[string]*blocksprovider.Deliverer{
			"a": {
				DoneC: make(chan struct{}),
			},
			"b": {
				DoneC: make(chan struct{}),
			},
		}

		ds.Stop()
		err := ds.StopDeliverForChannel("a")
		assert.EqualError(t, err, "Delivery service is stopping, cannot stop delivery for channel a")
	})

	t.Run("Non-existent", func(t *testing.T) {
		ds := NewDeliverService(&Config{}).(*deliverServiceImpl)
		ds.blockProviders = map[string]*blocksprovider.Deliverer{
			"a": {
				DoneC: make(chan struct{}),
			},
			"b": {
				DoneC: make(chan struct{}),
			},
		}

		err := ds.StopDeliverForChannel("c")
		assert.EqualError(t, err, "Delivery service - no block provider for c found, can't stop delivery")
	})
}

func TestStop(t *testing.T) {
	ds := NewDeliverService(&Config{}).(*deliverServiceImpl)
	ds.blockProviders = map[string]*blocksprovider.Deliverer{
		"a": {
			DoneC: make(chan struct{}),
		},
		"b": {
			DoneC: make(chan struct{}),
		},
	}
	assert.False(t, ds.stopping)
	for _, bp := range ds.blockProviders {
		select {
		case <-bp.DoneC:
			assert.Fail(t, "block providers should not be closed")
		default:
		}
	}

	ds.Stop()
	assert.True(t, ds.stopping)
	assert.Len(t, ds.blockProviders, 2)
	for _, bp := range ds.blockProviders {
		select {
		case <-bp.DoneC:
		default:
			assert.Fail(t, "block providers should te closed")
		}
	}

}
