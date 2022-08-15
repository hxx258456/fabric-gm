/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package channelparticipation

import (
	"errors"
	"fmt"

	"github.com/hxx258456/fabric-gm/bccsp/factory"
	"github.com/hxx258456/fabric-gm/common/channelconfig"
	"github.com/hxx258456/fabric-gm/protoutil"
	cb "github.com/hxx258456/fabric-protos-go-gm/common"
)

// ValidateJoinBlock returns whether this block can be used as a join block for the channel participation API
// and whether it is an system channel if it contains consortiums, or otherwise
// and application channel if an application group exists.
func ValidateJoinBlock(channelID string, configBlock *cb.Block) (isAppChannel bool, err error) {
	if !protoutil.IsConfigBlock(configBlock) {
		return false, errors.New("block is not a config block")
	}

	envelope, err := protoutil.ExtractEnvelope(configBlock, 0)
	if err != nil {
		return false, err
	}

	cryptoProvider := factory.GetDefault()
	bundle, err := channelconfig.NewBundleFromEnvelope(envelope, cryptoProvider)
	if err != nil {
		return false, err
	}

	// Check channel id from join block matches
	if bundle.ConfigtxValidator().ChannelID() != channelID {
		return false, fmt.Errorf("config block channelID [%s] does not match passed channelID [%s]",
			bundle.ConfigtxValidator().ChannelID(), channelID)
	}

	// Check channel type
	_, isSystemChannel := bundle.ConsortiumsConfig()
	if !isSystemChannel {
		_, isAppChannel = bundle.ApplicationConfig()
		if !isAppChannel {
			return false, errors.New("invalid config: must have at least one of application or consortiums")
		}
	}

	return isAppChannel, err
}
