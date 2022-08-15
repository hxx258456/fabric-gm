/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"fmt"
	"os"

	"gitee.com/zhaochuninhefei/fabric-chaincode-go-gm/shim"
	"github.com/hxx258456/fabric-gm/integration/chaincode/kvexecutor"
)

func main() {
	err := shim.Start(&kvexecutor.KVExcutor{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Exiting Simple chaincode: %s", err)
		os.Exit(2)
	}
}
