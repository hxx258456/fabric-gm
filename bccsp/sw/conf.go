/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"crypto/elliptic"
	"fmt"
	"hash"

	"github.com/hxx258456/ccgo/sm2"
	"github.com/hxx258456/ccgo/sm3"
)

/*
bccsp/sw/conf.go 提供bccsp配置
*/

type config struct {
	// // ECDSA的椭圆曲线
	// ecdsaCurve elliptic.Curve
	// // SHA的散列函数
	// shaFunction func() hash.Hash
	// // AES密钥位数
	// aesByteLength int
	// // RSA私钥位数
	// rsaBitLength int

	// 是否使用国密
	usingGM bool
	// 国密椭圆曲线
	gmCurve elliptic.Curve
	// 国密散列函数
	gmFunction func() hash.Hash
	// 国密密钥位数
	gmByteLength int
}

// 设置安全级别配置
func (conf *config) setSecurityLevel(usingGM bool, securityLevel int, hashFamily string) (err error) {
	// 国密对应，无视 usingGM ，固定使用国密
	conf.usingGM = true
	if securityLevel == 256 && hashFamily == "SM3" {
		_ = conf.setSecurityLevelWithSM2SM3()
	} else {
		err = fmt.Errorf("bccsp国密改造版目前只支持国密SM3 256位，不支持 [%s] [%d]位", hashFamily, securityLevel)
	}
	// if usingGM {
	// 	_ = conf.setSecurityLevelWithSM2SM3()
	// }
	// switch hashFamily {
	// case "SHA2":
	// 	err = conf.setSecurityLevelSHA2(securityLevel)
	// case "SHA3":
	// 	err = conf.setSecurityLevelSHA3(securityLevel)
	// default:
	// 	err = fmt.Errorf("国密的安全级别配置不支持 [%s]", hashFamily)
	// }
	return
}

// // 设置使用ecdsa与SHA2时的安全级别配置
// func (conf *config) setSecurityLevelSHA2(level int) (err error) {
// 	switch level {
// 	case 256:
// 		conf.ecdsaCurve = elliptic.P256()
// 		conf.shaFunction = sha256.New
// 		// conf.rsaBitLength = 2048
// 		conf.aesByteLength = 32
// 	case 384:
// 		conf.ecdsaCurve = elliptic.P384()
// 		conf.shaFunction = sha512.New384
// 		// conf.rsaBitLength = 3072
// 		conf.aesByteLength = 32
// 	default:
// 		err = fmt.Errorf("security level not supported [%d]", level)
// 	}
// 	return
// }

// // 设置使用ecdsa与SHA3时的安全级别配置
// func (conf *config) setSecurityLevelSHA3(level int) (err error) {
// 	switch level {
// 	case 256:
// 		conf.ecdsaCurve = elliptic.P256()
// 		conf.shaFunction = sha3.New256
// 		// conf.rsaBitLength = 2048
// 		conf.aesByteLength = 32
// 	case 384:
// 		conf.ecdsaCurve = elliptic.P384()
// 		conf.shaFunction = sha3.New384
// 		// conf.rsaBitLength = 3072
// 		conf.aesByteLength = 32
// 	default:
// 		err = fmt.Errorf("security level not supported [%d]", level)
// 	}
// 	return
// }

// 设置使用国密时的安全级别配置
func (conf *config) setSecurityLevelWithSM2SM3() (err error) {
	conf.gmCurve = sm2.P256Sm2()
	conf.gmFunction = sm3.New
	conf.gmByteLength = 16
	return nil
}
