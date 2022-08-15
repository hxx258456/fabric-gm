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
	"errors"

	"github.com/hxx258456/ccgo/sm3"
	"github.com/hxx258456/fabric-gm/bccsp"
)

/*
bccsp/sw/sm4key.go 定义国密sm4密钥结构体，并实现`bccsp.Key`(bccsp/bccsp.go)接口
*/

// 定义国密 SM4 结构体，实现 bccsp Key 的接口
type SM4Key struct {
	privKey    []byte
	exportable bool
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *SM4Key) Bytes() (raw []byte, err error) {
	if k.exportable {
		return k.privKey, nil
	}

	return nil, errors.New("not supported")
}

// SKI returns the subject key identifier of this key.
// 国密改造后散列算法改为SM3
func (k *SM4Key) SKI() (ski []byte) {
	hash := sm3.New()
	//hash := NewSM3()
	hash.Write([]byte{0x01})
	hash.Write(k.privKey)
	return hash.Sum(nil)
}

// Symmetric returns true if this key is a symmetric key,
// false if this key is asymmetric
func (k *SM4Key) Symmetric() bool {
	return true
}

// Private returns true if this key is a private key,
// false otherwise.
func (k *SM4Key) Private() bool {
	return true
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (k *SM4Key) PublicKey() (bccsp.Key, error) {
	return nil, errors.New("cannot call this method on a symmetric key")
}

func (k *SM4Key) InsideKey() interface{} {
	return k.privKey
}
