// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/hxx258456/fabric-gm/internal/configtxgen/encoder"
	"github.com/hxx258456/fabric-gm/internal/configtxgen/genesisconfig"
	"github.com/hxx258456/fabric-gm/internal/pkg/identity"
	cb "github.com/hxx258456/fabric-protos-go-gm/common"
)

func newChainRequest(
	consensusType,
	creationPolicy,
	newChannelID string,
	signer identity.SignerSerializer,
) *cb.Envelope {
	env, err := encoder.MakeChannelCreationTransaction(
		newChannelID,
		signer,
		genesisconfig.Load(genesisconfig.SampleSingleMSPChannelProfile),
	)
	if err != nil {
		panic(err)
	}
	return env
}
