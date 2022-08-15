/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package signer

import (
	"crypto/rand"
	"io/ioutil"

	"gitee.com/zhaochuninhefei/fabric-protos-go-gm/msp"
	"github.com/hxx258456/ccgo/sm2"
	"github.com/hxx258456/fabric-gm/bccsp/sw"
	"github.com/hxx258456/fabric-gm/bccsp/utils"
	"github.com/hxx258456/fabric-gm/common/util"
	"github.com/hxx258456/fabric-gm/protoutil"
	"github.com/pkg/errors"
)

/*
cmd/common/signer/signer.go 貌似是MSP的签名器
*/

// Config holds the configuration for
// creation of a Signer
type Config struct {
	MSPID string
	// 证书, 当前msp的证书?
	IdentityPath string
	// 私钥 当前msp的私钥?
	KeyPath string
}

// Signer signs messages.
// TODO: Ideally we'd use an MSP to be agnostic, but since it's impossible to
// initialize an MSP without a CA cert that signs the signing identity,
// this will do for now.
type Signer struct {
	key     *sm2.PrivateKey
	Creator []byte
}

func (si *Signer) Serialize() ([]byte, error) {
	return si.Creator, nil
}

// NewSigner creates a new Signer out of the given configuration
func NewSigner(conf Config) (*Signer, error) {
	// 序列化客户端mspid
	sId, err := serializeIdentity(conf.IdentityPath, conf.MSPID)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	// 读取私钥
	key, err := loadPrivateKey(conf.KeyPath)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	// 创建 Signer TODO: 在 Signer埋入 序列化客户端mspid 的目的是啥？
	return &Signer{
		Creator: sId,
		key:     key,
	}, nil
}

// 将客户端证书及MSPID组装为 protof格式的字节流
func serializeIdentity(clientCert string, mspID string) ([]byte, error) {
	b, err := ioutil.ReadFile(clientCert)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	sId := &msp.SerializedIdentity{
		Mspid:   mspID,
		IdBytes: b,
	}
	return protoutil.MarshalOrPanic(sId), nil
}

func (si *Signer) Sign(msg []byte) ([]byte, error) {
	digest := util.ComputeSM3(msg)
	return signSM2(si.key, digest)
}

// 将未加密的pem文件转为sm2私钥
func loadPrivateKey(file string) (*sm2.PrivateKey, error) {
	b, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	// bl, _ := pem.Decode(b)
	// if bl == nil {
	// 	return nil, errors.Errorf("failed to decode PEM block from %s", file)
	// }
	key, err := utils.PEMToSm2PrivateKey(b, nil)
	if err != nil {
		return nil, err
	}
	return key, nil
}

/*
// Based on crypto/tls/tls.go but modified for Fabric:
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	// OpenSSL 1.0.0 generates PKCS#8 keys.
	if key, err := sm2.ParsePKCS8UnecryptedPrivateKey(der); err == nil {
			switch key := key.(type) {
			// Fabric only supports ECDSA at the moment.
			case *ecdsa.PrivateKey:
				return key, nil
			default:
		return nil, errors.Errorf("found unknown private key type (%T) in PKCS#8 wrapping", key)
			}
			}

			// OpenSSL ecparam generates SEC1 EC private keys for ECDSA.
			key, err := sm2.P(der)
			if err != nil {
				return nil, errors.Errorf("failed to parse private key: %v", err)
			}
			return key, nil
}*/

func signSM2(k *sm2.PrivateKey, digest []byte) (signature []byte, err error) {
	r, s, err := sm2.Sm2Sign(k, digest, nil, rand.Reader)
	if err != nil {
		return nil, err
	}
	//s, err = utils.ToLowS(&k.PublicKey, s)
	if err != nil {
		return nil, err
	}

	return sw.MarshalSM2Signature(r, s)
}

// func signECDSA(k *ecdsa.PrivateKey, digest []byte) (signature []byte, err error) {
// 	r, s, err := ecdsa.Sign(rand.Reader, k, digest)
// 	if err != nil {
// 		return nil, err
// 	}

// 	s, err = utils.ToLowS(&k.PublicKey, s)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return marshalECDSASignature(r, s)
// }

// func marshalECDSASignature(r, s *big.Int) ([]byte, error) {
// 	return asn1.Marshal(ECDSASignature{r, s})
// }

// func marshalSM2Signature(r, s *big.Int) ([]byte, error) {
// 	return asn1.Marshal(sw.SM2Signature{R: r, S: s})
// }

// type ECDSASignature struct {
// 	R, S *big.Int
// }
