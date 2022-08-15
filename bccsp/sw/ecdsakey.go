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
package sw

/*
bccsp/sw/ecdsakey.go 定义ecdsa公私钥结构体，并实现`bccsp.Key`(bccsp/bccsp.go)接口
国密对应后废弃
*/

// import (
// 	"crypto/ecdsa"
// 	"crypto/elliptic"
// 	"crypto/sha256"
// 	"crypto/x509"
// 	"errors"
// 	"fmt"

// 	"github.com/hxx258456/fabric-gm/bccsp"
// )

// type ECDSAPrivateKey struct {
// 	privKey *ecdsa.PrivateKey
// }

// // Bytes converts this key to its byte representation,
// // if this operation is allowed.
// func (k *ECDSAPrivateKey) Bytes() ([]byte, error) {
// 	return nil, errors.New("not supported")
// }

// // SKI returns the subject key identifier of this key.
// func (k *ECDSAPrivateKey) SKI() []byte {
// 	if k.privKey == nil {
// 		return nil
// 	}

// 	// Marshall the public key
// 	raw := elliptic.Marshal(k.privKey.Curve, k.privKey.PublicKey.X, k.privKey.PublicKey.Y)

// 	// Hash it
// 	hash := sha256.New()
// 	hash.Write(raw)
// 	return hash.Sum(nil)
// }

// // Symmetric returns true if this key is a symmetric key,
// // false if this key is asymmetric
// func (k *ECDSAPrivateKey) Symmetric() bool {
// 	return false
// }

// // Private returns true if this key is a private key,
// // false otherwise.
// func (k *ECDSAPrivateKey) Private() bool {
// 	return true
// }

// // PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// // This method returns an error in symmetric key schemes.
// func (k *ECDSAPrivateKey) PublicKey() (bccsp.Key, error) {
// 	return &ECDSAPublicKey{&k.privKey.PublicKey}, nil
// }

// func (k *ECDSAPrivateKey) InsideKey() interface{} {
// 	return k.privKey
// }

// type ECDSAPublicKey struct {
// 	pubKey *ecdsa.PublicKey
// }

// // Bytes converts this key to its byte representation,
// // if this operation is allowed.
// func (k *ECDSAPublicKey) Bytes() (raw []byte, err error) {
// 	raw, err = x509.MarshalPKIXPublicKey(k.pubKey)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed marshalling key [%s]", err)
// 	}
// 	return
// }

// // SKI returns the subject key identifier of this key.
// func (k *ECDSAPublicKey) SKI() []byte {
// 	if k.pubKey == nil {
// 		return nil
// 	}

// 	// Marshall the public key
// 	raw := elliptic.Marshal(k.pubKey.Curve, k.pubKey.X, k.pubKey.Y)

// 	// Hash it
// 	hash := sha256.New()
// 	hash.Write(raw)
// 	return hash.Sum(nil)
// }

// // Symmetric returns true if this key is a symmetric key,
// // false if this key is asymmetric
// func (k *ECDSAPublicKey) Symmetric() bool {
// 	return false
// }

// // Private returns true if this key is a private key,
// // false otherwise.
// func (k *ECDSAPublicKey) Private() bool {
// 	return false
// }

// // PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// // This method returns an error in symmetric key schemes.
// func (k *ECDSAPublicKey) PublicKey() (bccsp.Key, error) {
// 	return k, nil
// }

// func (k *ECDSAPublicKey) InsideKey() interface{} {
// 	return k.pubKey
// }
