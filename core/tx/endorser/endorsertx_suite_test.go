/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package endorsertx_test

import (
	"math/rand"
	"testing"

	txpkg "github.com/hxx258456/fabric-gm/pkg/tx"
	"github.com/hxx258456/fabric-gm/protoutil"
	"github.com/hxx258456/fabric-protos-go-gm/common"
	"github.com/hxx258456/fabric-protos-go-gm/peer"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func randomLowerAlphaString(size int) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyz")
	output := make([]rune, size)
	for i := range output {
		output[i] = letters[rand.Intn(len(letters))]
	}
	return string(output)
}

func genTxEnvelope(
	hdrExt []byte,
	payloadData []byte,
	prpExt []byte,
	prp []byte,
	chHeader *common.ChannelHeader,
	sigHeader *common.SignatureHeader,
) *txpkg.Envelope {
	var hdrExtBytes []byte
	if hdrExt != nil {
		hdrExtBytes = hdrExt
	} else {
		hdrExtBytes = protoutil.MarshalOrPanic(
			&peer.ChaincodeHeaderExtension{
				ChaincodeId: &peer.ChaincodeID{
					Name: "my-called-cc",
				},
			},
		)
	}

	chHeader.Extension = hdrExtBytes

	var extBytes []byte
	if prpExt != nil {
		extBytes = prpExt
	} else {
		extBytes = protoutil.MarshalOrPanic(&peer.ChaincodeAction{
			Results: []byte("results"),
			Response: &peer.Response{
				Status: 200,
			},
			Events: []byte("events"),
		})
	}

	var prpBytes []byte
	if prp != nil {
		prpBytes = prp
	} else {
		prpBytes = protoutil.MarshalOrPanic(&peer.ProposalResponsePayload{
			Extension:    extBytes,
			ProposalHash: []byte("phash"),
		})
	}

	ccEndAct := &peer.ChaincodeEndorsedAction{
		ProposalResponsePayload: prpBytes,
		Endorsements: []*peer.Endorsement{
			{
				Endorser:  []byte("endorser"),
				Signature: []byte("signature"),
			},
		},
	}

	ccActP := &peer.ChaincodeActionPayload{
		Action: ccEndAct,
	}

	tx := &peer.Transaction{
		Actions: []*peer.TransactionAction{
			{
				Payload: protoutil.MarshalOrPanic(ccActP),
			},
		},
	}

	var txenvPayloadDataBytes []byte
	if payloadData != nil {
		txenvPayloadDataBytes = payloadData
	} else {
		txenvPayloadDataBytes = protoutil.MarshalOrPanic(tx)
	}

	return &txpkg.Envelope{
		ChannelHeader:   chHeader,
		SignatureHeader: sigHeader,
		Data:            txenvPayloadDataBytes,
	}
}

func TestEndorserTx(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "EndorserTx Suite")
}
