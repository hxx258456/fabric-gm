/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package filter

import (
	"context"
	"time"

	"github.com/hxx258456/fabric-gm/common/crypto"
	"github.com/hxx258456/fabric-gm/core/handlers/auth"
	"github.com/hxx258456/fabric-gm/protoutil"
	"github.com/hxx258456/fabric-protos-go-gm/peer"
	"github.com/pkg/errors"
)

// NewExpirationCheckFilter creates a new Filter that checks identity expiration
func NewExpirationCheckFilter() auth.Filter {
	return &expirationCheckFilter{}
}

type expirationCheckFilter struct {
	next peer.EndorserServer
}

// Init initializes the Filter with the next EndorserServer
func (f *expirationCheckFilter) Init(next peer.EndorserServer) {
	f.next = next
}

func validateProposal(signedProp *peer.SignedProposal) error {
	prop, err := protoutil.UnmarshalProposal(signedProp.ProposalBytes)
	if err != nil {
		return errors.Wrap(err, "failed parsing proposal")
	}

	hdr, err := protoutil.UnmarshalHeader(prop.Header)
	if err != nil {
		return errors.Wrap(err, "failed parsing header")
	}

	sh, err := protoutil.UnmarshalSignatureHeader(hdr.SignatureHeader)
	if err != nil {
		return errors.Wrap(err, "failed parsing signature header")
	}
	expirationTime := crypto.ExpiresAt(sh.Creator)
	if !expirationTime.IsZero() && time.Now().After(expirationTime) {
		return errors.New("proposal client identity expired")
	}
	return nil
}

// ProcessProposal processes a signed proposal
func (f *expirationCheckFilter) ProcessProposal(ctx context.Context, signedProp *peer.SignedProposal) (*peer.ProposalResponse, error) {
	if err := validateProposal(signedProp); err != nil {
		return nil, err
	}
	return f.next.ProcessProposal(ctx, signedProp)
}
