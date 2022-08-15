/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package channelconfig

import (
	"testing"

	cb "gitee.com/zhaochuninhefei/fabric-protos-go-gm/common"
	"github.com/stretchr/testify/assert"
)

func TestConsortiums(t *testing.T) {
	_, err := NewConsortiumsConfig(&cb.ConfigGroup{}, nil)
	assert.NoError(t, err)
}
