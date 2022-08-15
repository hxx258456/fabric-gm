/*
Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.

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
package sw

import (
	"crypto/elliptic"
	"fmt"

	"github.com/hxx258456/ccgo/sm2"
	"github.com/hxx258456/ccgo/sm3"
	"github.com/hxx258456/fabric-gm/bccsp"
)

/*
bccsp/sw/sm2key.go 用来定义国密sm2公私钥结构体，并分别实现`bccsp.Key`(bccsp/bccsp.go)接口
*/

type SM2PrivateKey struct {
	privKey *sm2.PrivateKey
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
// 获取sm2私钥的asn1编码结果，未对私钥加密
func (k *SM2PrivateKey) Bytes() (raw []byte, err error) {
	// return nil, errors.New("not supported")
	return privateKeyToDER(k.privKey)
}

// SKI returns the subject key identifier of this key.
// 国密改造后散列算法改为SM3
func (k *SM2PrivateKey) SKI() (ski []byte) {
	if k.privKey == nil {
		return nil
	}

	//Marshall the public key
	raw := elliptic.Marshal(k.privKey.Curve, k.privKey.PublicKey.X, k.privKey.PublicKey.Y)

	// Hash it
	hash := sm3.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *SM2PrivateKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *SM2PrivateKey) Private() bool {
	return true
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *SM2PrivateKey) PublicKey() (bccsp.Key, error) {
	return &SM2PublicKey{&k.privKey.PublicKey}, nil
}

func (k *SM2PrivateKey) InsideKey() interface{} {
	return k.privKey
}

type SM2PublicKey struct {
	pubKey *sm2.PublicKey
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
// 返回sm2公钥的asn1编码结果
func (k *SM2PublicKey) Bytes() (raw []byte, err error) {
	raw, err = publicKeyToDER(k.pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed marshalling key [%s]", err)
	}
	return
}

// SKI returns the subject key identifier of this key.
// 国密改造后散列算法改为SM3
func (k *SM2PublicKey) SKI() (ski []byte) {
	if k.pubKey == nil {
		return nil
	}

	// Marshall the public key
	raw := elliptic.Marshal(k.pubKey.Curve, k.pubKey.X, k.pubKey.Y)

	// Hash it
	hash := sm3.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *SM2PublicKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *SM2PublicKey) Private() bool {
	return false
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *SM2PublicKey) PublicKey() (bccsp.Key, error) {
	return k, nil
}

func (k *SM2PublicKey) InsideKey() interface{} {
	return k.pubKey
}
