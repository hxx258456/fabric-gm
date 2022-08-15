/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/hxx258456/ccgo/sm2"
	gmx509 "github.com/hxx258456/ccgo/x509"
	"github.com/hxx258456/fabric-gm/bccsp/utils"

	"github.com/hxx258456/fabric-gm/bccsp"
)

/*
bccsp/sw/keyimport.go 实现`sw.KeyImporter`接口(bccsp/sw/internals.go)
实现了以下几个密钥导入器:
aes256ImportKeyOptsKeyImporter 国密对应时去除
hmacImportKeyOptsKeyImporter 国密对应时去除
ecdsaPKIXPublicKeyImportOptsKeyImporter 国密对应时去除
ecdsaPrivateKeyImportOptsKeyImporter 国密对应时去除
ecdsaGoPublicKeyImportOptsKeyImporter 国密对应时去除
x509PublicKeyImportOptsKeyImporter 国密对应时去除
sm4ImportKeyOptsKeyImporter
sm2PrivateKeyOptsKeyImporter
sm2PublicKeyOptsKeyImporter
sm2GoPublicKeyOptsKeyImporter
*/

// // AES256位对称密钥导入器
// type aes256ImportKeyOptsKeyImporter struct{}

// func (*aes256ImportKeyOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
// 	aesRaw, ok := raw.([]byte)
// 	if !ok {
// 		return nil, errors.New("invalid raw material. Expected byte array")
// 	}

// 	if aesRaw == nil {
// 		return nil, errors.New("invalid raw material. It must not be nil")
// 	}

// 	if len(aesRaw) != 32 {
// 		return nil, fmt.Errorf("invalid Key Length [%d]. Must be 32 bytes", len(aesRaw))
// 	}

// 	return &AESPrivateKey{aesRaw, false}, nil
// }

// // HMac认证码导入器
// type hmacImportKeyOptsKeyImporter struct{}

// func (*hmacImportKeyOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
// 	aesRaw, ok := raw.([]byte)
// 	if !ok {
// 		return nil, errors.New("invalid raw material. Expected byte array")
// 	}

// 	if len(aesRaw) == 0 {
// 		return nil, errors.New("invalid raw material. It must not be nil")
// 	}

// 	return &AESPrivateKey{aesRaw, false}, nil
// }

// // 国密HMac认证码导入器
// type gmHmacImportKeyOptsKeyImporter struct{}

// func (*gmHmacImportKeyOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
// 	sm4Raw, ok := raw.([]byte)
// 	if !ok {
// 		return nil, errors.New("invalid raw material. Expected byte array")
// 	}

// 	if len(sm4Raw) == 0 {
// 		return nil, errors.New("invalid raw material. It must not be nil")
// 	}

// 	return &SM4Key{sm4Raw, false}, nil
// }

// // ECDSA公钥(PKIX标准der字节流)导入器
// type ecdsaPKIXPublicKeyImportOptsKeyImporter struct{}

// // 导入ECDSA公钥
// // raw : PKIX标准der字节流
// func (*ecdsaPKIXPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
// 	der, ok := raw.([]byte)
// 	if !ok {
// 		return nil, errors.New("invalid raw material. Expected byte array")
// 	}

// 	if len(der) == 0 {
// 		return nil, errors.New("invalid raw. It must not be nil")
// 	}

// 	lowLevelKey, err := derToPublicKey(der)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed converting PKIX to ECDSA public key [%s]", err)
// 	}

// 	ecdsaPK, ok := lowLevelKey.(*ecdsa.PublicKey)
// 	if !ok {
// 		return nil, errors.New("failed casting to ECDSA public key. Invalid raw material")
// 	}

// 	return &ECDSAPublicKey{ecdsaPK}, nil
// }

// // ECDSA私钥(PKCS#8标准der字节流)导入器
// type ecdsaPrivateKeyImportOptsKeyImporter struct{}

// // 导入ECDSA私钥
// // raw : PKCS#8标准der字节流
// func (*ecdsaPrivateKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
// 	der, ok := raw.([]byte)
// 	if !ok {
// 		return nil, errors.New("[ECDSADERPrivateKeyImportOpts] Invalid raw material. Expected byte array")
// 	}

// 	if len(der) == 0 {
// 		return nil, errors.New("[ECDSADERPrivateKeyImportOpts] Invalid raw. It must not be nil")
// 	}

// 	lowLevelKey, err := derToPrivateKey(der)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed converting PKIX to ECDSA public key [%s]", err)
// 	}

// 	ecdsaSK, ok := lowLevelKey.(*ecdsa.PrivateKey)
// 	if !ok {
// 		return nil, errors.New("failed casting to ECDSA private key. Invalid raw material")
// 	}

// 	return &ECDSAPrivateKey{ecdsaSK}, nil
// }

// // ECDSA公钥(Go结构体*ecdsa.PublicKey)导入器
// type ecdsaGoPublicKeyImportOptsKeyImporter struct{}

// // 导入ECDSA公钥
// // raw : *ecdsa.PublicKey
// func (*ecdsaGoPublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
// 	lowLevelKey, ok := raw.(*ecdsa.PublicKey)
// 	if !ok {
// 		return nil, errors.New("invalid raw material. Expected *ecdsa.PublicKey")
// 	}

// 	return &ECDSAPublicKey{lowLevelKey}, nil
// }

// // x509公钥导入器
// type x509PublicKeyImportOptsKeyImporter struct {
// 	bccsp *CSP
// }

// // 从x509证书导入公钥
// // raw : *x509.Certificate
// // 支持公钥: *ecdsa.PublicKey, *rsa.PublicKey
// func (ki *x509PublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
// 	cert, ok := raw.(*x509.Certificate)
// 	if !ok {
// 		return nil, errors.New("invalid raw material. Expected *x509.Certificate")
// 	}

// 	pk := cert.PublicKey

// 	switch pk := pk.(type) {
// 	case *ecdsa.PublicKey:
// 		return ki.bccsp.KeyImporters[reflect.TypeOf(&bccsp.ECDSAGoPublicKeyImportOpts{})].KeyImport(
// 			pk,
// 			&bccsp.ECDSAGoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
// 	case *rsa.PublicKey:
// 		// This path only exists to support environments that use RSA certificate
// 		// authorities to issue ECDSA certificates.
// 		return &rsaPublicKey{pubKey: pk}, nil
// 	default:
// 		return nil, errors.New("certificate's public key type not recognized. Supported keys: [SM2, ECDSA, RSA]")
// 	}
// }

// gmx509公钥导入器
type gmx509PublicKeyImportOptsKeyImporter struct {
	bccsp *CSP
}

// 从gmx509证书导入公钥
// raw : *gmx509.Certificate
// 支持公钥: *sm2.PublicKey, *ecdsa.PublicKey, *rsa.PublicKey
// 国密改造后只支持sm2
func (ki *gmx509PublicKeyImportOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	cert, ok := raw.(*gmx509.Certificate)
	if !ok {
		return nil, errors.New("invalid raw material. Expected *gmx509.Certificate")
	}

	pk := cert.PublicKey

	switch pk := pk.(type) {
	case *sm2.PublicKey:
		if !ok {
			return nil, errors.New("parse interface [] to sm2 pk error")
		}
		return ki.bccsp.KeyImporters[reflect.TypeOf(&bccsp.SM2GoPublicKeyImportOpts{})].KeyImport(
			pk,
			&bccsp.SM2GoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
	// case *ecdsa.PublicKey:
	// 	return ki.bccsp.KeyImporters[reflect.TypeOf(&bccsp.ECDSAGoPublicKeyImportOpts{})].KeyImport(
	// 		pk,
	// 		&bccsp.ECDSAGoPublicKeyImportOpts{Temporary: opts.Ephemeral()})
	// case *rsa.PublicKey:
	// 	// This path only exists to support environments that use RSA certificate
	// 	// authorities to issue ECDSA certificates.
	// 	return &rsaPublicKey{pubKey: pk}, nil
	default:
		return nil, errors.New("certificate's public key type not recognized. Supported keys: [SM2]")
	}
}

// sm4对称密钥导入器
type sm4ImportKeyOptsKeyImporter struct{}

func (*sm4ImportKeyOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	sm4Raw, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("invalid raw material, Expected byte array")
	}

	if sm4Raw == nil {
		return nil, errors.New("invalid raw material, It must botbe nil")
	}

	return &SM4Key{utils.Clone(sm4Raw), false}, nil
}

// sm2私钥(PKCS#8标准 或 SEC1标准的der字节流)导入器
type sm2PrivateKeyOptsKeyImporter struct{}

// sm2私钥导入
// raw : PKCS#8标准 或 SEC1标准 的der字节流
func (*sm2PrivateKeyOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("invalid raw material, Expected byte array")
	}

	if len(der) == 0 {
		return nil, errors.New("invalid raw material, It must botbe nil")
	}

	sm2SK, err := gmx509.ParsePKCS8PrivateKey(der)
	if err != nil {
		sm2SK, err = gmx509.ParseECPrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("failed converting to SM2 private key [%s]", err)
		}
	}
	privSm2, ok := sm2SK.(*sm2.PrivateKey)
	if !ok {
		return nil, errors.New("key type is not *sm2.PrivateKey")
	}
	return &SM2PrivateKey{privSm2}, nil
}

// sm2公钥(PKIX标准的der字节流)导入器
type sm2PublicKeyOptsKeyImporter struct{}

// sm2公钥导入
// raw : PKIX标准的der字节流
func (*sm2PublicKeyOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("invalid raw material, Expected byte array")
	}

	if len(der) == 0 {
		return nil, errors.New("invalid raw material, It must botbe nil")
	}

	sm2Pub, err := gmx509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("failed converting to SM2 private key [%s]", err)
	}
	pubSm2, ok := sm2Pub.(*sm2.PublicKey)
	if !ok {
		return nil, errors.New("key type is not *sm2.PublicKey")
	}
	return &SM2PublicKey{pubSm2}, nil
}

// sm2公钥(Go结构体*sm2.PublicKey)导入器
type sm2GoPublicKeyOptsKeyImporter struct{}

// sm2公钥导入
// raw : *sm2.PublicKey
func (*sm2GoPublicKeyOptsKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	lowLevelKey, ok := raw.(*sm2.PublicKey)
	if !ok {
		return nil, errors.New("invalid raw material. Expected *ecdsa.PublicKey")
	}

	return &SM2PublicKey{lowLevelKey}, nil
}
