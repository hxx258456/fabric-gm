/*
   Copyright (c) 2022 s1ren
   github.com/hxx258456/fabric-gm is licensed under Mulan PSL v2.
   You can use this software according to the terms and conditions of the Mulan PSL v2.
   You may obtain a copy of Mulan PSL v2 at:
            http://license.coscl.org.cn/MulanPSL2
   THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
   See the Mulan PSL v2 for more details.
*/

package cmd

import (
	"os"
	"strings"

	"gitee.com/zhaochuninhefei/zcgolog/zclog"
)

// 检查命令行中有无zclog日志级别设置参数，
// 有则设置zclog日志级别，并从os.Args中去除该参数。
func CheckZclogLevelFromOsArgs() {
	tempLevel := zclog.Level
	zclog.Level = zclog.LOG_LEVEL_DEBUG
	zclog.Debugf("===== before CheckZclogLevel os.Args: %s", os.Args)
	if len(os.Args) > 0 {
		var tmpArgs []string
		for _, arg := range os.Args {
			if strings.Index(arg, "--zclog-") == 0 {
				logLevelStr := arg[8:]
				tempLevel = zclog.GetLogLevelByStr(logLevelStr)
			} else {
				tmpArgs = append(tmpArgs, arg)
			}
		}
		os.Args = tmpArgs
	}
	zclog.Debugf("===== after CheckZclogLevel os.Args: %s", os.Args)
	zclog.Debugf("===== zclog日志级别: %s", zclog.GetLogLevelStrByInt(tempLevel))
	zclog.Level = tempLevel
}
