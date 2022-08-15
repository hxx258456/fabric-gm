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
package signer

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/hxx258456/ccgo/sm2"
	gmx509 "github.com/hxx258456/ccgo/x509"
	"github.com/hxx258456/fabric-gm/bccsp"
	"github.com/hxx258456/fabric-gm/bccsp/mocks"
	"github.com/hxx258456/fabric-gm/bccsp/sw"
	"github.com/stretchr/testify/assert"
)

func TestInitFailures(t *testing.T) {
	_, err := New(nil, &mocks.MockKey{})
	assert.Error(t, err)

	_, err = New(&mocks.MockBCCSP{}, nil)
	assert.Error(t, err)

	_, err = New(&mocks.MockBCCSP{}, &mocks.MockKey{Symm: true})
	assert.Error(t, err)

	_, err = New(&mocks.MockBCCSP{}, &mocks.MockKey{PKErr: errors.New("No PK")})
	assert.Error(t, err)
	assert.Equal(t, "failed getting public key: No PK", err.Error())

	_, err = New(&mocks.MockBCCSP{}, &mocks.MockKey{PK: &mocks.MockKey{BytesErr: errors.New("No bytes")}})
	assert.Error(t, err)
	assert.Equal(t, "failed marshalling public key: No bytes", err.Error())

	_, err = New(&mocks.MockBCCSP{}, &mocks.MockKey{PK: &mocks.MockKey{BytesValue: []byte{0, 1, 2, 3}}})
	assert.Error(t, err)
}

// func TestInit(t *testing.T) {
// 	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
// 	assert.NoError(t, err)
// 	pkRaw, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
// 	assert.NoError(t, err)

// 	signer, err := New(&mocks.MockBCCSP{}, &mocks.MockKey{PK: &mocks.MockKey{BytesValue: pkRaw}})
// 	assert.NoError(t, err)
// 	assert.NotNil(t, signer)

// 	// Test public key
// 	R, S, err := ecdsa.Sign(rand.Reader, k, []byte{0, 1, 2, 3})
// 	assert.NoError(t, err)
// 	fmt.Printf("签名: %d, %d\n", R, S)
// 	sign, _ := utils.MarshalECDSASignature(R, S)
// 	fmt.Printf("签名: %s", hex.EncodeToString(sign))

// 	assert.True(t, ecdsa.Verify(signer.Public().(*ecdsa.PublicKey), []byte{0, 1, 2, 3}, R, S))
// }

func TestInitSm2(t *testing.T) {
	k, err := sm2.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	pkRaw, err := gmx509.MarshalPKIXPublicKey(&k.PublicKey)
	assert.NoError(t, err)

	signer, err := New(&mocks.MockBCCSP{}, &mocks.MockKey{PK: &mocks.MockKey{BytesValue: pkRaw}})
	assert.NoError(t, err)
	assert.NotNil(t, signer)

	// Test public key
	R, S, err := sm2.Sm2Sign(k, []byte{0, 1, 2, 3}, nil, rand.Reader)
	assert.NoError(t, err)
	fmt.Printf("签名: %d, %d\n", R, S)
	sign, _ := sw.MarshalSM2Signature(R, S)
	fmt.Printf("签名: %s", hex.EncodeToString(sign))

	assert.True(t, sm2.Sm2Verify(signer.Public().(*sm2.PublicKey), []byte{0, 1, 2, 3}, nil, R, S))

}

func TestPublic(t *testing.T) {
	pk := &mocks.MockKey{}
	signer := &bccspCryptoSigner{pk: pk}

	pk2 := signer.Public()
	assert.NotNil(t, pk, pk2)
}

func TestSign(t *testing.T) {
	expectedSig := []byte{0, 1, 2, 3, 4}
	expectedKey := &mocks.MockKey{}
	expectedDigest := []byte{0, 1, 2, 3, 4, 5}
	expectedOpts := &mocks.SignerOpts{}

	signer := &bccspCryptoSigner{
		key: expectedKey,
		csp: &mocks.MockBCCSP{
			SignArgKey: expectedKey, SignDigestArg: expectedDigest, SignOptsArg: expectedOpts,
			SignValue: expectedSig}}
	signature, err := signer.Sign(nil, expectedDigest, expectedOpts)
	assert.NoError(t, err)
	assert.Equal(t, expectedSig, signature)

	signer = &bccspCryptoSigner{
		key: expectedKey,
		csp: &mocks.MockBCCSP{
			SignArgKey: expectedKey, SignDigestArg: expectedDigest, SignOptsArg: expectedOpts,
			SignErr: errors.New("no signature")}}
	_, err = signer.Sign(nil, expectedDigest, expectedOpts)
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "no signature")

	signer = &bccspCryptoSigner{
		key: nil,
		csp: &mocks.MockBCCSP{SignArgKey: expectedKey, SignDigestArg: expectedDigest, SignOptsArg: expectedOpts}}
	_, err = signer.Sign(nil, expectedDigest, expectedOpts)
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "invalid key")

	signer = &bccspCryptoSigner{
		key: expectedKey,
		csp: &mocks.MockBCCSP{SignArgKey: expectedKey, SignDigestArg: expectedDigest, SignOptsArg: expectedOpts}}
	_, err = signer.Sign(nil, nil, expectedOpts)
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "invalid digest")

	signer = &bccspCryptoSigner{
		key: expectedKey,
		csp: &mocks.MockBCCSP{SignArgKey: expectedKey, SignDigestArg: expectedDigest, SignOptsArg: expectedOpts}}
	_, err = signer.Sign(nil, expectedDigest, nil)
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "invalid opts")
}

func TestSignSm2(t *testing.T) {
	expectedDigest := []byte{0, 1, 2, 3, 4, 5}
	csp, err := sw.NewDefaultSecurityLevelWithKeystore(sw.NewDummyKeyStore())
	if err != nil {
		t.Fatalf("获取csp失败: %s\n", err)
	}
	key, err := csp.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: true})
	if err != nil {
		t.Fatalf("生成key失败: %s\n", err)
	}
	signer := &bccspCryptoSigner{
		key: key,
		csp: csp,
	}
	sign, err := signer.Sign(rand.Reader, expectedDigest, nil)
	if err != nil {
		t.Fatalf("签名失败: %s\n", err)
	}
	fmt.Printf("签名: %s", hex.EncodeToString(sign))
	r, s, err := sw.UnmarshalSM2Signature(sign)
	if err != nil {
		t.Fatalf("签名转rs失败: %s\n", err)
	}
	fmt.Printf("签名: %d, %d\n", r, s)

	pub, err := key.PublicKey()
	if err != nil {
		t.Fatalf("签名转rs失败: %s\n", err)
	}
	ok, err := csp.Verify(pub, sign, expectedDigest, nil)
	if err != nil {
		t.Fatalf("签名转rs失败: %s\n", err)
	}
	fmt.Printf("验签结果: %v\n", ok)
}
