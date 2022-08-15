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
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/hxx258456/ccgo/sm2"
	"github.com/hxx258456/fabric-gm/bccsp"
)

/*
bccsp/sw/sm2.go 实现`sw.Signer`接口和`sw.Verifier`接口(bccsp/sw/internals.go)
去除了lowS相关处理
*/

type SM2Signature struct {
	R, S *big.Int
}

// var (
// 	// curveHalfOrders contains the precomputed curve group orders halved.
// 	// It is used to ensure that signature' S value is lower or equal to the
// 	// curve group order halved. We accept only low-S signatures.
// 	// They are precomputed for efficiency reasons.
// 	curveHalfOrders map[elliptic.Curve]*big.Int = map[elliptic.Curve]*big.Int{
// 		elliptic.P224(): new(big.Int).Rsh(elliptic.P224().Params().N, 1),
// 		elliptic.P256(): new(big.Int).Rsh(elliptic.P256().Params().N, 1),
// 		elliptic.P384(): new(big.Int).Rsh(elliptic.P384().Params().N, 1),
// 		elliptic.P521(): new(big.Int).Rsh(elliptic.P521().Params().N, 1),
// 		sm2.P256Sm2():   new(big.Int).Rsh(sm2.P256Sm2().Params().N, 1),
// 	}
// )

// 对签名(r,s)做asn1编码
func MarshalSM2Signature(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(SM2Signature{r, s})
}

// 对asn1编码的签名做解码
func UnmarshalSM2Signature(raw []byte) (*big.Int, *big.Int, error) {
	// Unmarshal
	sig := new(SM2Signature)
	_, err := asn1.Unmarshal(raw, sig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed unmashalling signature [%s]", err)
	}

	// Validate sig
	if sig.R == nil {
		return nil, nil, errors.New("invalid signature. R must be different from nil")
	}
	if sig.S == nil {
		return nil, nil, errors.New("invalid signature. S must be different from nil")
	}

	if sig.R.Sign() != 1 {
		return nil, nil, errors.New("invalid signature. R must be larger than zero")
	}
	if sig.S.Sign() != 1 {
		return nil, nil, errors.New("invalid signature. S must be larger than zero")
	}

	return sig.R, sig.S, nil
}

// 国密sm2签名，digest是内容摘要，opts实际没有使用
func signSM2(k *sm2.PrivateKey, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	signature, err = k.Sign(rand.Reader, digest, opts)
	return
}

// 国密sm2验签，digest是内容摘要，signature是被验签的签名，opts实际没有使用
func verifySM2(k *sm2.PublicKey, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	valid = k.Verify(digest, signature)
	/*fmt.Printf("valid+++,%v", valid)*/
	return
}

type sm2Signer struct{}

// 在sm2Signer上绑定Sign签名方法
func (s *sm2Signer) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	return signSM2(k.(*SM2PrivateKey).privKey, digest, opts)
}

// TODO 下面这种明面上是ecdsa实际上是sm2的做法没有意义。
// 因为最终生成密钥对的时候，还是必须用sm2的椭圆曲线。

// type ecdsaPrivateKeySigner struct{}

// // 在ecdsaPrivateKeySigner上绑定Sign签名方法，内部转为sm2签名。
// // 注意，k明面上是ecdsa私钥，但其实内部所有参数都是sm2的参数(Curve、X、Y、D)。
// func (s *ecdsaPrivateKeySigner) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
// 	// 如果k的类型不是`ecdsaPrivateKey`，比如是`sm2PrivateKey`，那么这里会出错。
// 	// 但后续又将ecdsaPrivateKey的Curve、X、Y、D直接拿来当作sm2.PublicKey与sm2.PrivateKey的相关参数，
// 	// 因此必须满足条件：k明面上是ecdsa私钥，但其实内部所有参数(Curve、X、Y、D)都是sm2的。
// 	puk := k.(*ecdsaPrivateKey).privKey.PublicKey
// 	sm2pk := sm2.PublicKey{
// 		Curve: puk.Curve,
// 		X:     puk.X,
// 		Y:     puk.Y,
// 	}
// 	privKey := k.(*ecdsaPrivateKey).privKey
// 	sm2privKey := sm2.PrivateKey{
// 		D:         privKey.D,
// 		PublicKey: sm2pk,
// 	}
// 	return signSM2(&sm2privKey, digest, opts)
// }

type sm2PrivateKeyVerifier struct{}

// 在sm2PrivateKeyVerifier上绑定验签方法
func (v *sm2PrivateKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	return verifySM2(&(k.(*SM2PrivateKey).privKey.PublicKey), signature, digest, opts)
}

type sm2PublicKeyKeyVerifier struct{}

// 在sm2PublicKeyKeyVerifier上绑定验签方法
func (v *sm2PublicKeyKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	return verifySM2(k.(*SM2PublicKey).pubKey, signature, digest, opts)
}

// TODO 下面这种明面上是ecdsa实际上是sm2的做法没有意义。
// 因为最终生成密钥对的时候，还是必须用sm2的椭圆曲线。

// type ecdsaPrivateKeyVerifier struct{}

// // 在ecdsaPrivateKeyVerifier上绑定Verify验签方法，内部转为sm2验签。
// // 注意，k明面上是ecdsa私钥，但其实内部所有参数都是sm2的参数(Curve、X、Y、D)。
// func (v *ecdsaPrivateKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
// 	puk := k.(*ecdsaPrivateKey).privKey.PublicKey
// 	sm2pk := sm2.PublicKey{
// 		Curve: puk.Curve,
// 		X:     puk.X,
// 		Y:     puk.Y,
// 	}
// 	return verifySM2(&sm2pk, signature, digest, opts)
// }

// type ecdsaPublicKeyKeyVerifier struct{}

// // 在ecdsaPublicKeyKeyVerifier上绑定Verify验签方法，内部转为sm2验签。
// // 注意，k明面上是ecdsa公钥，但其实内部所有参数都是sm2的参数(Curve、X、Y)。
// func (v *ecdsaPublicKeyKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
// 	puk := k.(*ecdsaPublicKey).pubKey
// 	sm2pk := sm2.PublicKey{
// 		Curve: puk.Curve,
// 		X:     puk.X,
// 		Y:     puk.Y,
// 	}
// 	return verifySM2(&sm2pk, signature, digest, opts)
// }
