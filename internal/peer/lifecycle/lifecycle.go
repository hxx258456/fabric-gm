/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lifecycle

import (
	"github.com/hxx258456/fabric-gm/bccsp"
	"github.com/hxx258456/fabric-gm/internal/peer/lifecycle/chaincode"
	"github.com/spf13/cobra"
)

// Cmd returns the cobra command for lifecycle
func Cmd(cryptoProvider bccsp.BCCSP) *cobra.Command {
	lifecycleCmd := &cobra.Command{
		Use:   "lifecycle",
		Short: "Perform _lifecycle operations",
		Long:  "Perform _lifecycle operations",
	}
	lifecycleCmd.AddCommand(chaincode.Cmd(cryptoProvider))

	return lifecycleCmd
}
