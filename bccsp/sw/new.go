/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"reflect"

	"github.com/hxx258456/ccgo/sm3"

	"github.com/hxx258456/fabric-gm/bccsp"
	"github.com/pkg/errors"
)

/*
bccsp/sw/new.go 提供创建`sw.CSP`(bccsp/sw/impl.go)的函数:
NewDefaultSecurityLevel
NewDefaultSecurityLevelWithKeystore
NewWithParams
默认hashFamily改为SM3
*/

// NewDefaultSecurityLevel returns a new instance of the software-based BCCSP
// at security level 256, hash family SHA2 and using FolderBasedKeyStore as KeyStore.
func NewDefaultSecurityLevel(keyStorePath string) (bccsp.BCCSP, error) {
	ks := &fileBasedKeyStore{}
	if err := ks.Init(nil, keyStorePath, false); err != nil {
		return nil, errors.Wrapf(err, "Failed initializing key store at [%v]", keyStorePath)
	}
	// 改为使用国密
	// return NewWithParams(256, "SHA2", ks)
	return NewWithParams(true, 256, "SM3", ks)
}

// NewDefaultSecurityLevel returns a new instance of the software-based BCCSP
// at security level 256, hash family SHA2 and using the passed KeyStore.
func NewDefaultSecurityLevelWithKeystore(keyStore bccsp.KeyStore) (bccsp.BCCSP, error) {
	// 改为使用国密
	// return NewWithParams(256, "SHA2", keyStore)
	return NewWithParams(true, 256, "SM3", keyStore)
}

// NewWithParams returns a new instance of the software-based BCCSP
// set at the passed security level, hash family and KeyStore.
// 根据参数生成swbccsp
func NewWithParams(usingGM bool, securityLevel int, hashFamily string, keyStore bccsp.KeyStore) (bccsp.BCCSP, error) {
	// Init config
	conf := &config{}
	err := conf.setSecurityLevel(usingGM, securityLevel, hashFamily)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed initializing configuration at [%v,%v]", securityLevel, hashFamily)
	}

	swbccsp, err := New(keyStore)
	if err != nil {
		return nil, err
	}

	// Notice that errors are ignored here because some test will fail if one
	// of the following call fails.

	// 添加国密相关组件 无视 usingGM 固定使用国密组件
	// if usingGM {
	// Set the key generators
	// sm2密钥对构造器
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM2KeyGenOpts{}), &sm2KeyGenerator{})
	// sm4密钥构造器
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM4KeyGenOpts{}), &sm4KeyGenerator{length: conf.gmByteLength})

	// Set the key deriver
	// 国密没有密钥派生相关实现

	// Set the key importers
	// sm2私钥导入器
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM2PrivateKeyImportOpts{}), &sm2PrivateKeyOptsKeyImporter{})
	// sm2公钥导入器
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM2PublicKeyImportOpts{}), &sm2PublicKeyOptsKeyImporter{})
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM2GoPublicKeyImportOpts{}), &sm2GoPublicKeyOptsKeyImporter{})
	// sm4密钥导入器
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM4ImportKeyOpts{}), &sm4ImportKeyOptsKeyImporter{})
	// gmx509公钥导入，x509的签名内容的核心是证书拥有者的公钥，与签名算法无关，因此可能是sm2,ecdsa或rsa
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.GMX509PublicKeyImportOpts{}), &gmx509PublicKeyImportOptsKeyImporter{bccsp: swbccsp})
	// // 国密HMac认证码导入器
	// swbccsp.AddWrapper(reflect.TypeOf(&bccsp.GMHMACImportKeyOpts{}), &gmHmacImportKeyOptsKeyImporter{})

	// Set the Hashers
	// sm3散列
	swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SM3Opts{}), &hasher{hash: sm3.New})

	// Set the Signers
	// sm2私钥签名
	swbccsp.AddWrapper(reflect.TypeOf(&SM2PrivateKey{}), &sm2Signer{})

	// Set the Verifiers
	// sm2公钥验签
	swbccsp.AddWrapper(reflect.TypeOf(&SM2PublicKey{}), &sm2PublicKeyKeyVerifier{})
	// sm2私钥验签，实际还是公钥验签
	swbccsp.AddWrapper(reflect.TypeOf(&SM2PrivateKey{}), &sm2PrivateKeyVerifier{})

	// Set the Encryptors
	// sm4加密，未分组 --> 该问题已对应，修改了`bccsp/sw/sm4.go`的sm4Encryptor与sm4Decryptor的接口实现方法
	swbccsp.AddWrapper(reflect.TypeOf(&SM4Key{}), &sm4Encryptor{})

	// Set the Decryptors
	// sm4解密，未分组 --> 该问题已对应，修改了`bccsp/sw/sm4.go`的sm4Encryptor与sm4Decryptor的接口实现方法
	swbccsp.AddWrapper(reflect.TypeOf(&SM4Key{}), &sm4Decryptor{})

	swbccsp.Algorithms = "sm2-sm3-sm4"
	// }

	// 国密对应后，去除所有非国密的密码组件
	// // Set the Encryptors
	// swbccsp.AddWrapper(reflect.TypeOf(&AESPrivateKey{}), &aescbcpkcs7Encryptor{})
	// // Set the Decryptors
	// swbccsp.AddWrapper(reflect.TypeOf(&AESPrivateKey{}), &aescbcpkcs7Decryptor{})
	// // Set the Signers
	// // ecdsa签名
	// swbccsp.AddWrapper(reflect.TypeOf(&ECDSAPrivateKey{}), &ecdsaSigner{})
	// // Set the Verifiers
	// // ecdsa私钥验签，实际还是公钥验签 已改回真实的ecdsa实现
	// swbccsp.AddWrapper(reflect.TypeOf(&ECDSAPrivateKey{}), &ecdsaPrivateKeyVerifier{})
	// // ecdsa公钥验签 已改回真实的ecdsa实现
	// swbccsp.AddWrapper(reflect.TypeOf(&ECDSAPublicKey{}), &ecdsaPublicKeyKeyVerifier{})
	// // Set the Hashers
	// swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SHAOpts{}), &hasher{hash: conf.shaFunction})
	// swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SHA256Opts{}), &hasher{hash: sha256.New})
	// swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SHA384Opts{}), &hasher{hash: sha512.New384})
	// swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SHA3_256Opts{}), &hasher{hash: sha3.New256})
	// swbccsp.AddWrapper(reflect.TypeOf(&bccsp.SHA3_384Opts{}), &hasher{hash: sha3.New384})
	// // Set the key generators
	// // ecdsaKeyGenerator是真实的ecdsa的密钥对构造，不是sm2的密钥对
	// swbccsp.AddWrapper(reflect.TypeOf(&bccsp.ECDSAKeyGenOpts{}), &ecdsaKeyGenerator{curve: conf.ecdsaCurve})
	// swbccsp.AddWrapper(reflect.TypeOf(&bccsp.ECDSAP256KeyGenOpts{}), &ecdsaKeyGenerator{curve: elliptic.P256()})
	// swbccsp.AddWrapper(reflect.TypeOf(&bccsp.ECDSAP384KeyGenOpts{}), &ecdsaKeyGenerator{curve: elliptic.P384()})
	// swbccsp.AddWrapper(reflect.TypeOf(&bccsp.AESKeyGenOpts{}), &aesKeyGenerator{length: conf.aesByteLength})
	// swbccsp.AddWrapper(reflect.TypeOf(&bccsp.AES256KeyGenOpts{}), &aesKeyGenerator{length: 32})
	// swbccsp.AddWrapper(reflect.TypeOf(&bccsp.AES192KeyGenOpts{}), &aesKeyGenerator{length: 24})
	// swbccsp.AddWrapper(reflect.TypeOf(&bccsp.AES128KeyGenOpts{}), &aesKeyGenerator{length: 16})
	// // Set the key deriver
	// swbccsp.AddWrapper(reflect.TypeOf(&ECDSAPrivateKey{}), &ecdsaPrivateKeyKeyDeriver{})
	// swbccsp.AddWrapper(reflect.TypeOf(&ECDSAPublicKey{}), &ecdsaPublicKeyKeyDeriver{})
	// swbccsp.AddWrapper(reflect.TypeOf(&AESPrivateKey{}), &aesPrivateKeyKeyDeriver{conf: conf})
	// // Set the key importers
	// swbccsp.AddWrapper(reflect.TypeOf(&bccsp.AES256ImportKeyOpts{}), &aes256ImportKeyOptsKeyImporter{})
	// swbccsp.AddWrapper(reflect.TypeOf(&bccsp.HMACImportKeyOpts{}), &hmacImportKeyOptsKeyImporter{})
	// swbccsp.AddWrapper(reflect.TypeOf(&bccsp.ECDSAPKIXPublicKeyImportOpts{}), &ecdsaPKIXPublicKeyImportOptsKeyImporter{})
	// swbccsp.AddWrapper(reflect.TypeOf(&bccsp.ECDSAPrivateKeyImportOpts{}), &ecdsaPrivateKeyImportOptsKeyImporter{})
	// swbccsp.AddWrapper(reflect.TypeOf(&bccsp.ECDSAGoPublicKeyImportOpts{}), &ecdsaGoPublicKeyImportOptsKeyImporter{})
	// // x509公钥导入，x509的签名内容的核心是证书拥有者的公钥，与签名算法无关，因此可能是ecdsa或rsa
	// swbccsp.AddWrapper(reflect.TypeOf(&bccsp.X509PublicKeyImportOpts{}), &x509PublicKeyImportOptsKeyImporter{bccsp: swbccsp})
	// swbccsp.Algorithms = swbccsp.Algorithms + "ecdsa-sha-aes"
	return swbccsp, nil
}
