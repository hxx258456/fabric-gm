/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package protoutil

import "gitee.com/zhaochuninhefei/fabric-protos-go-gm/common"

func NewConfigGroup() *common.ConfigGroup {
	return &common.ConfigGroup{
		Groups:   make(map[string]*common.ConfigGroup),
		Values:   make(map[string]*common.ConfigValue),
		Policies: make(map[string]*common.ConfigPolicy),
	}
}
