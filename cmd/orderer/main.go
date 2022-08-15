/*
Copyright IBM Corp. 2017 All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package main is the entrypoint for the orderer binary
// and calls only into the server.Main() function.  No other
// function should be included in this package.
package main

import (
	"github.com/hxx258456/fabric-gm/cmd"
	"github.com/hxx258456/fabric-gm/orderer/common/server"
)

func main() {
	// 检查zclog日志级别并设置
	cmd.CheckZclogLevelFromOsArgs()
	server.Main()
}
