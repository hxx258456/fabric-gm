/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package testutil

import (
	"github.com/hxx258456/fabric-gm/core/ledger/pvtdatapolicy"
	"github.com/hxx258456/fabric-gm/core/ledger/pvtdatapolicy/mock"
	"github.com/hxx258456/fabric-protos-go-gm/peer"
)

// SampleBTLPolicy helps tests create a sample BTLPolicy
// The example input entry is [2]string{ns, coll}:btl
func SampleBTLPolicy(m map[[2]string]uint64) pvtdatapolicy.BTLPolicy {
	ccInfoRetriever := &mock.CollectionInfoProvider{}
	ccInfoRetriever.CollectionInfoStub = func(ccName, collName string) (*peer.StaticCollectionConfig, error) {
		btl := m[[2]string{ccName, collName}]
		return &peer.StaticCollectionConfig{BlockToLive: btl}, nil
	}
	return pvtdatapolicy.ConstructBTLPolicy(ccInfoRetriever)
}
