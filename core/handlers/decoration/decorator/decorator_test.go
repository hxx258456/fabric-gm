/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package decorator

import (
	"testing"

	"gitee.com/zhaochuninhefei/fabric-protos-go-gm/peer"
	"github.com/stretchr/testify/assert"
)

func TestDecorator(t *testing.T) {
	dec := NewDecorator()
	in := &peer.ChaincodeInput{
		Args: [][]byte{{1, 2, 3}},
	}
	out := dec.Decorate(nil, in)
	assert.Equal(t, in, out)
}
