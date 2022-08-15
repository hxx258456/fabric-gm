//go:build pkcs11
// +build pkcs11

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package factory

/*
bccsp/factory/pkcs11factory.go 国密对应后废弃
*/

// import (
// 	"encoding/hex"

// 	"github.com/hxx258456/fabric-gm/bccsp"
// 	"github.com/hxx258456/fabric-gm/bccsp/pkcs11"
// 	"github.com/hxx258456/fabric-gm/bccsp/sw"
// 	"github.com/pkg/errors"
// )

// /*
// bccsp/factory/pkcs11factory.go 定义 PKCS11Factory 结构体并为其实现`factory.BCCSPFactory`接口(bccsp/factory/factory.go)
// 需要添加编译条件: `pkcs11`
// */

// const (
// 	// PKCS11BasedFactoryName is the name of the factory of the hsm-based BCCSP implementation
// 	PKCS11BasedFactoryName = "PKCS11"
// )

// // PKCS11Factory is the factory of the HSM-based BCCSP.
// type PKCS11Factory struct{}

// // Name returns the name of this factory
// func (f *PKCS11Factory) Name() string {
// 	return PKCS11BasedFactoryName
// }

// // Get returns an instance of BCCSP using Opts.
// func (f *PKCS11Factory) Get(config *FactoryOpts) (bccsp.BCCSP, error) {
// 	// Validate arguments
// 	if config == nil || config.Pkcs11Opts == nil {
// 		return nil, errors.New("Invalid config. It must not be nil.")
// 	}

// 	p11Opts := *config.Pkcs11Opts
// 	ks := sw.NewDummyKeyStore()
// 	mapper := skiMapper(p11Opts)

// 	return pkcs11.New(p11Opts, ks, pkcs11.WithKeyMapper(mapper))
// }

// func skiMapper(p11Opts pkcs11.PKCS11Opts) func([]byte) []byte {
// 	keyMap := map[string]string{}
// 	for _, k := range p11Opts.KeyIDs {
// 		keyMap[k.SKI] = k.ID
// 	}

// 	return func(ski []byte) []byte {
// 		keyID := hex.EncodeToString(ski)
// 		if id, ok := keyMap[keyID]; ok {
// 			return []byte(id)
// 		}
// 		if p11Opts.AltID != "" {
// 			return []byte(p11Opts.AltID)
// 		}
// 		return ski
// 	}
// }
