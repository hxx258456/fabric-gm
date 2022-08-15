//go:build !pkcs11
// +build !pkcs11

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package factory

import (
	"github.com/hxx258456/fabric-gm/bccsp"
	"github.com/pkg/errors"
)

/*
bccsp/factory/nopkcs11.go 为 SWFactory 提供 FactoryOpts 以及相关函数。
在不添加编译条件`pkcs11`时生效
*/

const pkcs11Enabled = false

// TODO 注意这里定义的FactoryOpts不会与`pkcs11.go`里定义的FactoryOpts冲突，因为该文件头声明了编译条件是 `!pkcs11`，而`pkcs11.go`的编译条件是`pkcs11`
// FactoryOpts holds configuration information used to initialize factory implementations
type FactoryOpts struct {
	ProviderName string  `mapstructure:"default" json:"default" yaml:"Default"`
	SwOpts       *SwOpts `mapstructure:"SW,omitempty" json:"SW,omitempty" yaml:"SwOpts"`
	UsingGM      string  `mapstructure:"usingGM,omitempty" json:"usingGM,omitempty" yaml:"usingGM,omitempty"`
}

// InitFactories must be called before using factory interfaces
// It is acceptable to call with config = nil, in which case
// some defaults will get used
// Error is returned only if defaultBCCSP cannot be found
func InitFactories(config *FactoryOpts) error {
	factoriesInitOnce.Do(func() {
		factoriesInitError = initFactories(config)
	})

	return factoriesInitError
}

func initFactories(config *FactoryOpts) error {
	// Take some precautions on default opts
	if config == nil {
		config = GetDefaultOpts()
	}

	if config.ProviderName == "" {
		config.ProviderName = "SW"
	}

	if config.SwOpts == nil {
		config.SwOpts = GetDefaultOpts().SwOpts
	}

	if config.UsingGM == "" {
		config.UsingGM = "Y"
	}

	// Software-Based BCCSP
	if config.ProviderName == "SW" && config.SwOpts != nil {
		f := &SWFactory{}
		var err error
		defaultBCCSP, err = initBCCSP(f, config)
		if err != nil {
			return errors.Wrapf(err, "Failed initializing BCCSP")
		}
	}
	// // Software-Based BCCSP
	// if config.ProviderName == "GM" && config.SwOpts != nil {
	// 	f := &GMFactory{}
	// 	var err error
	// 	defaultBCCSP, err = initBCCSP(f, config)
	// 	if err != nil {
	// 		return errors.Wrapf(err, "Failed initializing BCCSP")
	// 	}
	// }

	if defaultBCCSP == nil {
		return errors.Errorf("Could not find default `%s` BCCSP", config.ProviderName)
	}

	return nil
}

// GetBCCSPFromOpts returns a BCCSP created according to the options passed in input.
func GetBCCSPFromOpts(config *FactoryOpts) (bccsp.BCCSP, error) {
	var f BCCSPFactory
	switch config.ProviderName {
	// case "GM":
	// 	f = &GMFactory{}
	case "SW":
		f = &SWFactory{}
	default:
		return nil, errors.Errorf("Could not find BCCSP, no '%s' provider", config.ProviderName)
	}

	csp, err := f.Get(config)
	if err != nil {
		return nil, errors.Wrapf(err, "Could not initialize BCCSP %s", f.Name())
	}
	return csp, nil
}
