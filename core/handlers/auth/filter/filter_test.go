/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package filter

import (
	"context"
	"testing"

	"gitee.com/zhaochuninhefei/fabric-protos-go-gm/peer"
	"github.com/stretchr/testify/assert"
)

type mockEndorserServer struct {
	invoked bool
}

func (es *mockEndorserServer) ProcessProposal(context.Context, *peer.SignedProposal) (*peer.ProposalResponse, error) {
	es.invoked = true
	return nil, nil
}

func TestFilter(t *testing.T) {
	auth := NewFilter()
	nextEndorser := &mockEndorserServer{}
	auth.Init(nextEndorser)
	auth.ProcessProposal(context.Background(), nil)
	assert.True(t, nextEndorser.invoked)
}
