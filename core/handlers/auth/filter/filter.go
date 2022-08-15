/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package filter

import (
	"context"

	"github.com/hxx258456/fabric-gm/core/handlers/auth"
	"github.com/hxx258456/fabric-protos-go-gm/peer"
)

// NewFilter creates a new Filter
func NewFilter() auth.Filter {
	return &filter{}
}

type filter struct {
	next peer.EndorserServer
}

// Init initializes the Filter with the next EndorserServer
func (f *filter) Init(next peer.EndorserServer) {
	f.next = next
}

// ProcessProposal processes a signed proposal
func (f *filter) ProcessProposal(ctx context.Context, signedProp *peer.SignedProposal) (*peer.ProposalResponse, error) {
	return f.next.ProcessProposal(ctx, signedProp)
}
