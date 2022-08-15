// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	cb "gitee.com/zhaochuninhefei/fabric-protos-go-gm/common"
	"github.com/hxx258456/fabric-gm/internal/configtxgen/encoder"
	"github.com/hxx258456/fabric-gm/internal/configtxgen/genesisconfig"
	"github.com/hxx258456/fabric-gm/internal/pkg/identity"
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
