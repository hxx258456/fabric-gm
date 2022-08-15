/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"os"

	"github.com/hxx258456/fabric-gm/bccsp/factory"
	"github.com/hxx258456/fabric-gm/cmd"
	"github.com/hxx258456/fabric-gm/cmd/common"
	discovery "github.com/hxx258456/fabric-gm/discovery/cmd"
)

func main() {
	// 检查zclog日志级别并设置
	cmd.CheckZclogLevelFromOsArgs()
	factory.InitFactories(nil)
	cli := common.NewCLI("discover", "Command line client for fabric discovery service")
	discovery.AddCommands(cli)
	cli.Run(os.Args[1:])
}
