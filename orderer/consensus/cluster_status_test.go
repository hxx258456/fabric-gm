/*
Copyright IBM Corp. 2017 All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package consensus_test

import (
	"testing"

	"github.com/hxx258456/fabric-gm/orderer/common/types"

	"github.com/hxx258456/fabric-gm/orderer/consensus"
	"github.com/stretchr/testify/assert"
)

func TestStaticStatusReporter(t *testing.T) {
	staticSR := &consensus.StaticStatusReporter{
		ClusterRelation: types.ClusterRelationNone,
		Status:          types.StatusActive,
	}

	var sr consensus.StatusReporter = staticSR // make sure it implements this interface
	cRel, status := sr.StatusReport()
	assert.Equal(t, types.ClusterRelationNone, cRel)
	assert.Equal(t, types.StatusActive, status)
}
