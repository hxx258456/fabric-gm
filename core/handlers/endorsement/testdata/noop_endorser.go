/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	endorsement "github.com/hxx258456/fabric-gm/core/handlers/endorsement/api"
	"github.com/hxx258456/fabric-protos-go-gm/peer"
)

type NoOpEndorser struct {
}

func (*NoOpEndorser) Endorse(payload []byte, sp *peer.SignedProposal) (*peer.Endorsement, []byte, error) {
	return nil, payload, nil
}

func (*NoOpEndorser) Init(dependencies ...endorsement.Dependency) error {
	return nil
}

type NoOpEndorserFactory struct {
}

func (*NoOpEndorserFactory) New() endorsement.Plugin {
	return &NoOpEndorser{}
}

// NewPluginFactory is the function ran by the plugin infrastructure to create an endorsement plugin factory.
func NewPluginFactory() endorsement.PluginFactory {
	return &NoOpEndorserFactory{}
}
