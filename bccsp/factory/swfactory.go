/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package factory

import (
	"github.com/hxx258456/fabric-gm/bccsp"
	"github.com/hxx258456/fabric-gm/bccsp/sw"
	"github.com/pkg/errors"
)

/*
bccsp/factory/swfactory.go 定义 SWFactory 结构体并为其实现`factory.BCCSPFactory`接口(bccsp/factory/factory.go)
*/

const (
	// SoftwareBasedFactoryName is the name of the factory of the software-based BCCSP implementation
	SoftwareBasedFactoryName = "SW"
)

// SWFactory is the factory of the software-based BCCSP.
type SWFactory struct{}

// Name returns the name of this factory
func (f *SWFactory) Name() string {
	return SoftwareBasedFactoryName
}

// Get returns an instance of BCCSP using Opts.
func (f *SWFactory) Get(config *FactoryOpts) (bccsp.BCCSP, error) {
	// Validate arguments
	if config == nil || config.SwOpts == nil {
		return nil, errors.New("Invalid config. It must not be nil.")
	}

	swOpts := config.SwOpts

	var ks bccsp.KeyStore
	switch {
	case swOpts.Ephemeral:
		ks = sw.NewDummyKeyStore()
	case swOpts.FileKeystore != nil:
		fks, err := sw.NewFileBasedKeyStore(nil, swOpts.FileKeystore.KeyStorePath, false)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to initialize software key store")
		}
		ks = fks
	case swOpts.InmemKeystore != nil:
		ks = sw.NewInMemoryKeyStore()
	default:
		// Default to ephemeral key store
		ks = sw.NewDummyKeyStore()
	}

	var usingGM bool
	switch config.UsingGM {
	case "Y", "y":
		usingGM = true
	case "N", "n":
		usingGM = false
	default:
		usingGM = true
	}

	return sw.NewWithParams(usingGM, swOpts.SecLevel, swOpts.HashFamily, ks)
}

// SwOpts contains options for the SWFactory
// 用于 SWFactory 的相关配置
type SwOpts struct {
	// Default algorithms when not specified (Deprecated?)
	// 算法强度，国密对应后只支持256
	SecLevel int `mapstructure:"security" json:"security" yaml:"Security"`
	// 散列算法，国密对应后只支持SM3
	HashFamily string `mapstructure:"hash" json:"hash" yaml:"Hash"`

	// Keystore Options
	// Ephemeral为true时使用DummyKeystore
	// Ephemeral、FileKeystore、InmemKeystore相互之间互斥
	Ephemeral     bool               `mapstructure:"tempkeys,omitempty" json:"tempkeys,omitempty"`
	FileKeystore  *FileKeystoreOpts  `mapstructure:"filekeystore,omitempty" json:"filekeystore,omitempty" yaml:"FileKeyStore"`
	DummyKeystore *DummyKeystoreOpts `mapstructure:"dummykeystore,omitempty" json:"dummykeystore,omitempty"`
	InmemKeystore *InmemKeystoreOpts `mapstructure:"inmemkeystore,omitempty" json:"inmemkeystore,omitempty"`
}

// Pluggable Keystores, could add JKS, P12, etc..
type FileKeystoreOpts struct {
	KeyStorePath string `mapstructure:"keystore" yaml:"KeyStore"`
}

type DummyKeystoreOpts struct{}

// InmemKeystoreOpts - empty, as there is no config for the in-memory keystore
type InmemKeystoreOpts struct{}
