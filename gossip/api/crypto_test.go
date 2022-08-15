/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

import (
	"encoding/pem"
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/hxx258456/fabric-gm/protoutil"
	"github.com/hxx258456/fabric-protos-go-gm/msp"
	"github.com/stretchr/testify/assert"
)

func TestPeerIdentityTypeString(t *testing.T) {
	certBytes, err := ioutil.ReadFile(filepath.Join("testdata", "peer.pem"))
	assert.NoError(t, err)

	for _, testCase := range []struct {
		description string
		identity    PeerIdentityType
		expectedOut string
	}{
		{
			description: "non serialized identity",
			identity:    PeerIdentityType("some garbage"),
			expectedOut: "non SerializedIdentity: c29tZSBnYXJiYWdl",
		},
		{
			description: "non PEM identity",
			identity: PeerIdentityType(protoutil.MarshalOrPanic(&msp.SerializedIdentity{
				Mspid:   "SampleOrg",
				IdBytes: []byte{1, 2, 3},
			})),
			expectedOut: "non PEM encoded identity: CglTYW1wbGVPcmcSAwECAw==",
		},
		{
			description: "non x509 identity",
			identity: PeerIdentityType(protoutil.MarshalOrPanic(&msp.SerializedIdentity{
				Mspid: "SampleOrg",
				IdBytes: pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: []byte{1, 2, 3},
				}),
			})),
			expectedOut: `non x509 identity: CglTYW1wbGVPcmcSOy0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQpBUUlECi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K`,
		},
		{
			description: "x509 identity",
			identity: PeerIdentityType(protoutil.MarshalOrPanic(&msp.SerializedIdentity{
				Mspid:   "SampleOrg",
				IdBytes: certBytes,
			})),
			expectedOut: `{"CN":"peer0.org1.example.com","Issuer-CN":"ca.org1.example.com","Issuer-L-ST-C":"[Hefei]-[Anhui]-[CN]","Issuer-OU":["gcbaas"],"L-ST-C":"[Hefei]-[Anhui]-[CN]","MSP":"SampleOrg","OU":["gcbaas"]}`,
		},
	} {
		t.Run(testCase.description, func(t *testing.T) {
			assert.Equal(t, testCase.identity.String(), testCase.expectedOut)
		})
	}

}
