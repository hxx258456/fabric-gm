/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"bytes"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/hxx258456/fabric-gm/bccsp"
	"github.com/hxx258456/fabric-gm/bccsp/signer"
	"github.com/hxx258456/fabric-gm/bccsp/sw/mocks"
	"github.com/stretchr/testify/assert"

	gmx509 "github.com/hxx258456/ccgo/x509"
)

var (
	currentTestConfig testConfig
	tempDir           string
)

type testConfig struct {
	usingGM       bool
	securityLevel int
	hashFamily    string
}

func (tc testConfig) Provider(t *testing.T) (bccsp.BCCSP, bccsp.KeyStore, func()) {
	td, err := ioutil.TempDir(tempDir, "test")
	assert.NoError(t, err)
	ks, err := NewFileBasedKeyStore(nil, td, false)
	assert.NoError(t, err)
	p, err := NewWithParams(tc.usingGM, tc.securityLevel, tc.hashFamily, ks)
	assert.NoError(t, err)
	return p, ks, func() { os.RemoveAll(td) }
}

func TestMain(m *testing.M) {
	code := -1
	defer func() {
		os.Exit(code)
	}()
	tests := []testConfig{
		// {true, 256, "SHA2"},
		// {false, 256, "SHA3"},
		// {true, 384, "SHA2"},
		// {false, 384, "SHA3"},
		{true, 256, "SM3"},
	}

	var err error
	tempDir, err = ioutil.TempDir("", "bccsp-sw")
	if err != nil {
		fmt.Printf("Failed to create temporary directory: %s\n\n", err)
		return
	}
	defer os.RemoveAll(tempDir)

	for _, config := range tests {
		currentTestConfig = config
		code = m.Run()
		if code != 0 {
			fmt.Printf("Failed testing at [%d, %s]", config.securityLevel, config.hashFamily)
			return
		}
	}
}

func TestInvalidNewParameter(t *testing.T) {
	t.Parallel()
	_, ks, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	r, err := NewWithParams(true, 0, "SHA2", ks)
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}
	if r != nil {
		t.Fatal("Return value should be equal to nil in this case")
	}

	r, err = NewWithParams(true, 256, "SM3", ks)
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}
	if r != nil {
		t.Fatal("Return value should be equal to nil in this case")
	}

	r, err = NewWithParams(true, 256, "SHA2", nil)
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}
	if r != nil {
		t.Fatal("Return value should be equal to nil in this case")
	}

	r, err = NewWithParams(true, 0, "SHA3", nil)
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}
	if r != nil {
		t.Fatal("Return value should be equal to nil in this case")
	}

	r, err = NewDefaultSecurityLevel("")
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}
	if r != nil {
		t.Fatal("Return value should be equal to nil in this case")
	}
}

func TestInvalidSKI(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	k, err := provider.GetKey(nil)
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}
	if k != nil {
		t.Fatal("Return value should be equal to nil in this case")
	}

	k, err = provider.GetKey([]byte{0, 1, 2, 3, 4, 5, 6})
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}
	if k != nil {
		t.Fatal("Return value should be equal to nil in this case")
	}
}

// func TestKeyGenECDSAOpts(t *testing.T) {
// 	t.Parallel()
// 	provider, _, cleanup := currentTestConfig.Provider(t)
// 	defer cleanup()

// 	// Curve P256
// 	k, err := provider.KeyGen(&bccsp.ECDSAP256KeyGenOpts{Temporary: false})
// 	if err != nil {
// 		t.Fatalf("Failed generating ECDSA P256 key [%s]", err)
// 	}
// 	if k == nil {
// 		t.Fatal("Failed generating ECDSA P256 key. Key must be different from nil")
// 	}
// 	if !k.Private() {
// 		t.Fatal("Failed generating ECDSA P256 key. Key should be private")
// 	}
// 	if k.Symmetric() {
// 		t.Fatal("Failed generating ECDSA P256 key. Key should be asymmetric")
// 	}

// 	ecdsaKey := k.(*ECDSAPrivateKey).privKey
// 	if !elliptic.P256().IsOnCurve(ecdsaKey.X, ecdsaKey.Y) {
// 		t.Fatal("P256 generated key in invalid. The public key must be on the P256 curve.")
// 	}
// 	if elliptic.P256() != ecdsaKey.Curve {
// 		t.Fatal("P256 generated key in invalid. The curve must be P256.")
// 	}
// 	if ecdsaKey.D.Cmp(big.NewInt(0)) == 0 {
// 		t.Fatal("P256 generated key in invalid. Private key must be different from 0.")
// 	}

// 	// Curve P384
// 	k, err = provider.KeyGen(&bccsp.ECDSAP384KeyGenOpts{Temporary: false})
// 	if err != nil {
// 		t.Fatalf("Failed generating ECDSA P384 key [%s]", err)
// 	}
// 	if k == nil {
// 		t.Fatal("Failed generating ECDSA P384 key. Key must be different from nil")
// 	}
// 	if !k.Private() {
// 		t.Fatal("Failed generating ECDSA P384 key. Key should be private")
// 	}
// 	if k.Symmetric() {
// 		t.Fatal("Failed generating ECDSA P384 key. Key should be asymmetric")
// 	}

// 	ecdsaKey = k.(*ECDSAPrivateKey).privKey
// 	if !elliptic.P384().IsOnCurve(ecdsaKey.X, ecdsaKey.Y) {
// 		t.Fatal("P256 generated key in invalid. The public key must be on the P384 curve.")
// 	}
// 	if elliptic.P384() != ecdsaKey.Curve {
// 		t.Fatal("P256 generated key in invalid. The curve must be P384.")
// 	}
// 	if ecdsaKey.D.Cmp(big.NewInt(0)) == 0 {
// 		t.Fatal("P256 generated key in invalid. Private key must be different from 0.")
// 	}

// }

// func TestKeyGenAESOpts(t *testing.T) {
// 	t.Parallel()
// 	provider, _, cleanup := currentTestConfig.Provider(t)
// 	defer cleanup()

// 	// AES 128
// 	k, err := provider.KeyGen(&bccsp.AES128KeyGenOpts{Temporary: false})
// 	if err != nil {
// 		t.Fatalf("Failed generating AES 128 key [%s]", err)
// 	}
// 	if k == nil {
// 		t.Fatal("Failed generating AES 128 key. Key must be different from nil")
// 	}
// 	if !k.Private() {
// 		t.Fatal("Failed generating AES 128 key. Key should be private")
// 	}
// 	if !k.Symmetric() {
// 		t.Fatal("Failed generating AES 128 key. Key should be symmetric")
// 	}

// 	aesKey := k.(*AESPrivateKey).privKey
// 	if len(aesKey) != 16 {
// 		t.Fatal("AES Key generated key in invalid. The key must have length 16.")
// 	}

// 	// AES 192
// 	k, err = provider.KeyGen(&bccsp.AES192KeyGenOpts{Temporary: false})
// 	if err != nil {
// 		t.Fatalf("Failed generating AES 192 key [%s]", err)
// 	}
// 	if k == nil {
// 		t.Fatal("Failed generating AES 192 key. Key must be different from nil")
// 	}
// 	if !k.Private() {
// 		t.Fatal("Failed generating AES 192 key. Key should be private")
// 	}
// 	if !k.Symmetric() {
// 		t.Fatal("Failed generating AES 192 key. Key should be symmetric")
// 	}

// 	aesKey = k.(*AESPrivateKey).privKey
// 	if len(aesKey) != 24 {
// 		t.Fatal("AES Key generated key in invalid. The key must have length 16.")
// 	}

// 	// AES 256
// 	k, err = provider.KeyGen(&bccsp.AES256KeyGenOpts{Temporary: false})
// 	if err != nil {
// 		t.Fatalf("Failed generating AES 256 key [%s]", err)
// 	}
// 	if k == nil {
// 		t.Fatal("Failed generating AES 256 key. Key must be different from nil")
// 	}
// 	if !k.Private() {
// 		t.Fatal("Failed generating AES 256 key. Key should be private")
// 	}
// 	if !k.Symmetric() {
// 		t.Fatal("Failed generating AES 256 key. Key should be symmetric")
// 	}

// 	aesKey = k.(*AESPrivateKey).privKey
// 	if len(aesKey) != 32 {
// 		t.Fatal("AES Key generated key in invalid. The key must have length 16.")
// 	}
// }

// func TestECDSAKeyGenEphemeral(t *testing.T) {
// 	t.Parallel()
// 	provider, _, cleanup := currentTestConfig.Provider(t)
// 	defer cleanup()

// 	k, err := provider.KeyGen(&bccsp.ECDSAKeyGenOpts{Temporary: true})
// 	if err != nil {
// 		t.Fatalf("Failed generating ECDSA key [%s]", err)
// 	}
// 	if k == nil {
// 		t.Fatal("Failed generating ECDSA key. Key must be different from nil")
// 	}
// 	if !k.Private() {
// 		t.Fatal("Failed generating ECDSA key. Key should be private")
// 	}
// 	if k.Symmetric() {
// 		t.Fatal("Failed generating ECDSA key. Key should be asymmetric")
// 	}
// 	raw, err := k.Bytes()
// 	if err == nil {
// 		t.Fatal("Failed marshalling to bytes. Marshalling must fail.")
// 	}
// 	if len(raw) != 0 {
// 		t.Fatal("Failed marshalling to bytes. Output should be 0 bytes")
// 	}
// 	pk, err := k.PublicKey()
// 	if err != nil {
// 		t.Fatalf("Failed getting corresponding public key [%s]", err)
// 	}
// 	if pk == nil {
// 		t.Fatal("Public key must be different from nil.")
// 	}
// }

// func TestECDSAPrivateKeySKI(t *testing.T) {
// 	t.Parallel()
// 	provider, _, cleanup := currentTestConfig.Provider(t)
// 	defer cleanup()

// 	k, err := provider.KeyGen(&bccsp.ECDSAKeyGenOpts{Temporary: false})
// 	if err != nil {
// 		t.Fatalf("Failed generating ECDSA key [%s]", err)
// 	}

// 	ski := k.SKI()
// 	if len(ski) == 0 {
// 		t.Fatal("SKI not valid. Zero length.")
// 	}
// }

// func TestECDSAKeyGenNonEphemeral(t *testing.T) {
// 	t.Parallel()
// 	provider, _, cleanup := currentTestConfig.Provider(t)
// 	defer cleanup()

// 	k, err := provider.KeyGen(&bccsp.ECDSAKeyGenOpts{Temporary: false})
// 	if err != nil {
// 		t.Fatalf("Failed generating ECDSA key [%s]", err)
// 	}
// 	if k == nil {
// 		t.Fatal("Failed generating ECDSA key. Key must be different from nil")
// 	}
// 	if !k.Private() {
// 		t.Fatal("Failed generating ECDSA key. Key should be private")
// 	}
// 	if k.Symmetric() {
// 		t.Fatal("Failed generating ECDSA key. Key should be asymmetric")
// 	}
// }

func TestECDSAGetKeyBySKI(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	var k bccsp.Key
	var err error
	switch currentTestConfig.usingGM {
	case true:
		fmt.Println("生成 SM2 key")
		k, err = provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
		// default:
		// 	fmt.Println("生成 ECDSA key")
		// 	k, err = provider.KeyGen(&bccsp.ECDSAKeyGenOpts{Temporary: false})
	}
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	k2, err := provider.GetKey(k.SKI())
	if err != nil {
		t.Fatalf("Failed getting ECDSA key [%s]", err)
	}
	if k2 == nil {
		t.Fatal("Failed getting ECDSA key. Key must be different from nil")
	}
	if !k2.Private() {
		t.Fatal("Failed getting ECDSA key. Key should be private")
	}
	if k2.Symmetric() {
		t.Fatal("Failed getting ECDSA key. Key should be asymmetric")
	}

	// Check that the SKIs are the same
	if !bytes.Equal(k.SKI(), k2.SKI()) {
		t.Fatalf("SKIs are different [%x]!=[%x]", k.SKI(), k2.SKI())
	}
}

// func TestECDSAPublicKeyFromPrivateKey(t *testing.T) {
// 	t.Parallel()
// 	provider, _, cleanup := currentTestConfig.Provider(t)
// 	defer cleanup()

// 	k, err := provider.KeyGen(&bccsp.ECDSAKeyGenOpts{Temporary: false})
// 	if err != nil {
// 		t.Fatalf("Failed generating ECDSA key [%s]", err)
// 	}

// 	pk, err := k.PublicKey()
// 	if err != nil {
// 		t.Fatalf("Failed getting public key from private ECDSA key [%s]", err)
// 	}
// 	if pk == nil {
// 		t.Fatal("Failed getting public key from private ECDSA key. Key must be different from nil")
// 	}
// 	if pk.Private() {
// 		t.Fatal("Failed generating ECDSA key. Key should be public")
// 	}
// 	if pk.Symmetric() {
// 		t.Fatal("Failed generating ECDSA key. Key should be asymmetric")
// 	}
// }

func TestECDSAPublicKeyBytes(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	var k bccsp.Key
	var err error
	switch currentTestConfig.usingGM {
	case true:
		fmt.Println("生成 SM2 key")
		k, err = provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
		// default:
		// 	fmt.Println("生成 ECDSA key")
		// 	k, err = provider.KeyGen(&bccsp.ECDSAKeyGenOpts{Temporary: false})
	}
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting public key from private ECDSA key [%s]", err)
	}

	raw, err := pk.Bytes()
	if err != nil {
		t.Fatalf("Failed marshalling ECDSA public key [%s]", err)
	}
	if len(raw) == 0 {
		t.Fatal("Failed marshalling ECDSA public key. Zero length")
	}
}

// func TestECDSAPublicKeySKI(t *testing.T) {
// 	t.Parallel()
// 	provider, _, cleanup := currentTestConfig.Provider(t)
// 	defer cleanup()

// 	k, err := provider.KeyGen(&bccsp.ECDSAKeyGenOpts{Temporary: false})
// 	if err != nil {
// 		t.Fatalf("Failed generating ECDSA key [%s]", err)
// 	}

// 	pk, err := k.PublicKey()
// 	if err != nil {
// 		t.Fatalf("Failed getting public key from private ECDSA key [%s]", err)
// 	}

// 	ski := pk.SKI()
// 	if len(ski) == 0 {
// 		t.Fatal("SKI not valid. Zero length.")
// 	}
// }

// func TestECDSAKeyReRand(t *testing.T) {
// 	t.Parallel()
// 	provider, _, cleanup := currentTestConfig.Provider(t)
// 	defer cleanup()

// 	k, err := provider.KeyGen(&bccsp.ECDSAKeyGenOpts{Temporary: false})
// 	if err != nil {
// 		t.Fatalf("Failed generating ECDSA key [%s]", err)
// 	}
// 	if k == nil {
// 		t.Fatal("Failed re-randomizing ECDSA key. Re-randomized Key must be different from nil")
// 	}

// 	reRandomizedKey, err := provider.KeyDeriv(k, &bccsp.ECDSAReRandKeyOpts{Temporary: false, Expansion: []byte{1}})
// 	if err != nil {
// 		t.Fatalf("Failed re-randomizing ECDSA key [%s]", err)
// 	}
// 	if !reRandomizedKey.Private() {
// 		t.Fatal("Failed re-randomizing ECDSA key. Re-randomized Key should be private")
// 	}
// 	if reRandomizedKey.Symmetric() {
// 		t.Fatal("Failed re-randomizing ECDSA key. Re-randomized Key should be asymmetric")
// 	}

// 	k2, err := k.PublicKey()
// 	if err != nil {
// 		t.Fatalf("Failed getting public ECDSA key from private [%s]", err)
// 	}
// 	if k2 == nil {
// 		t.Fatal("Failed re-randomizing ECDSA key. Re-randomized Key must be different from nil")
// 	}

// 	reRandomizedKey2, err := provider.KeyDeriv(k2, &bccsp.ECDSAReRandKeyOpts{Temporary: false, Expansion: []byte{1}})
// 	if err != nil {
// 		t.Fatalf("Failed re-randomizing ECDSA key [%s]", err)
// 	}

// 	if reRandomizedKey2.Private() {
// 		t.Fatal("Re-randomized public Key must remain public")
// 	}
// 	if reRandomizedKey2.Symmetric() {
// 		t.Fatal("Re-randomized ECDSA asymmetric key must remain asymmetric")
// 	}

// 	if false == bytes.Equal(reRandomizedKey.SKI(), reRandomizedKey2.SKI()) {
// 		t.Fatal("Re-randomized ECDSA Private- or Public-Keys must end up having the same SKI")
// 	}
// }

func TestECDSASign(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	var k bccsp.Key
	var err error
	switch currentTestConfig.usingGM {
	case true:
		fmt.Println("生成 SM2 key")
		k, err = provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
		// default:
		// 	fmt.Println("生成 ECDSA key")
		// 	k, err = provider.KeyGen(&bccsp.ECDSAKeyGenOpts{Temporary: false})
	}
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	msg := []byte("Hello World")

	var digest []byte
	switch currentTestConfig.usingGM {
	case true:
		fmt.Println("SM2 不需要预先对签名内容做摘要")
		digest = msg
		// default:
		// 	fmt.Println("ECDSA 需要预先对签名内容做摘要")
		// 	digest, err = provider.Hash(msg, &bccsp.SHAOpts{})
		// 	if err != nil {
		// 		t.Fatalf("Failed computing HASH [%s]", err)
		// 	}
	}
	if err != nil {
		t.Fatalf("Failed computing HASH [%s]", err)
	}

	signature, err := provider.Sign(k, digest, nil)
	if err != nil {
		t.Fatalf("Failed generating ECDSA signature [%s]", err)
	}
	if len(signature) == 0 {
		t.Fatal("Failed generating ECDSA key. Signature must be different from nil")
	}
}

func TestECDSAVerify(t *testing.T) {
	t.Parallel()
	provider, ks, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	var k bccsp.Key
	var err error
	switch currentTestConfig.usingGM {
	case true:
		fmt.Println("生成 SM2 key")
		k, err = provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
		// default:
		// 	fmt.Println("生成 ECDSA key")
		// 	k, err = provider.KeyGen(&bccsp.ECDSAKeyGenOpts{Temporary: false})
	}
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	msg := []byte("Hello World")
	var digest []byte
	switch currentTestConfig.usingGM {
	case true:
		fmt.Println("SM2 不需要预先对签名内容做摘要")
		digest = msg
		// default:
		// 	fmt.Println("ECDSA 需要预先对签名内容做摘要")
		// 	digest, err = provider.Hash(msg, &bccsp.SHAOpts{})
		// 	if err != nil {
		// 		t.Fatalf("Failed computing HASH [%s]", err)
		// 	}
	}
	if err != nil {
		t.Fatalf("Failed computing HASH [%s]", err)
	}

	signature, err := provider.Sign(k, digest, nil)
	if err != nil {
		t.Fatalf("Failed generating ECDSA signature [%s]", err)
	}

	valid, err := provider.Verify(k, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying ECDSA signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying ECDSA signature. Signature not valid.")
	}

	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting corresponding public key [%s]", err)
	}

	valid, err = provider.Verify(pk, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying ECDSA signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying ECDSA signature. Signature not valid.")
	}

	// Store public key
	err = ks.StoreKey(pk)
	if err != nil {
		t.Fatalf("Failed storing corresponding public key [%s]", err)
	}

	pk2, err := ks.GetKey(pk.SKI())
	if err != nil {
		t.Fatalf("Failed retrieving corresponding public key [%s]", err)
	}

	valid, err = provider.Verify(pk2, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying ECDSA signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying ECDSA signature. Signature not valid.")
	}
}

// func TestECDSAKeyDeriv(t *testing.T) {
// 	t.Parallel()
// 	provider, _, cleanup := currentTestConfig.Provider(t)
// 	defer cleanup()

// 	k, err := provider.KeyGen(&bccsp.ECDSAKeyGenOpts{Temporary: false})
// 	if err != nil {
// 		t.Fatalf("Failed generating ECDSA key [%s]", err)
// 	}

// 	reRandomizedKey, err := provider.KeyDeriv(k, &bccsp.ECDSAReRandKeyOpts{Temporary: false, Expansion: []byte{1}})
// 	if err != nil {
// 		t.Fatalf("Failed re-randomizing ECDSA key [%s]", err)
// 	}

// 	msg := []byte("Hello World")

// 	digest, err := provider.Hash(msg, &bccsp.SHAOpts{})
// 	if err != nil {
// 		t.Fatalf("Failed computing HASH [%s]", err)
// 	}

// 	signature, err := provider.Sign(reRandomizedKey, digest, nil)
// 	if err != nil {
// 		t.Fatalf("Failed generating ECDSA signature [%s]", err)
// 	}

// 	valid, err := provider.Verify(reRandomizedKey, signature, digest, nil)
// 	if err != nil {
// 		t.Fatalf("Failed verifying ECDSA signature [%s]", err)
// 	}
// 	if !valid {
// 		t.Fatal("Failed verifying ECDSA signature. Signature not valid.")
// 	}
// }

func TestECDSAKeyImportFromExportedKey(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	var k bccsp.Key
	var err error
	switch currentTestConfig.usingGM {
	case true:
		// 生成sm2 key
		fmt.Println("生成 SM2 key")
		k, err = provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
		// default:
		// 	// Generate an ECDSA key
		// 	fmt.Println("生成 ECDSA key")
		// 	k, err = provider.KeyGen(&bccsp.ECDSAKeyGenOpts{Temporary: false})
	}
	if err != nil {
		t.Fatalf("Failed generating ECDSA/SM2 key [%s]", err)
	}

	// Export the public key
	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting ECDSA/SM2 public key [%s]", err)
	}

	pkRaw, err := pk.Bytes()
	if err != nil {
		t.Fatalf("Failed getting ECDSA/SM2 raw public key [%s]", err)
	}

	// Import the exported public key
	var pk2 bccsp.Key
	switch currentTestConfig.usingGM {
	case true:
		fmt.Println("SM2 KeyImport")
		pk2, err = provider.KeyImport(pkRaw, &bccsp.SM2PublicKeyImportOpts{Temporary: false})
		// default:
		// 	fmt.Println("ECDSA KeyImport")
		// 	pk2, err = provider.KeyImport(pkRaw, &bccsp.ECDSAPKIXPublicKeyImportOpts{Temporary: false})
	}
	if err != nil {
		t.Fatalf("Failed importing ECDSA/SM2 public key [%s]", err)
	}
	if pk2 == nil {
		t.Fatal("Failed importing ECDSA/SM2 public key. Return BCCSP key cannot be nil.")
	}

	// Sign and verify with the imported public key
	msg := []byte("Hello World")

	var digest []byte
	switch currentTestConfig.usingGM {
	case true:
		fmt.Println("SM2 不需要预先对签名内容做摘要")
		digest = msg
		// default:
		// 	fmt.Println("ECDSA 需要预先对签名内容做摘要")
		// 	digest, err = provider.Hash(msg, &bccsp.SHAOpts{})
		// 	if err != nil {
		// 		t.Fatalf("Failed computing HASH [%s]", err)
		// 	}
	}

	signature, err := provider.Sign(k, digest, nil)
	if err != nil {
		t.Fatalf("Failed generating ECDSA/SM2 signature [%s]", err)
	}

	valid, err := provider.Verify(pk2, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying ECDSA/SM2 signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying ECDSA/SM2 signature. Signature not valid.")
	}
}

func TestECDSAKeyImportFromECDSAPublicKey(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	var k bccsp.Key
	var err error
	switch currentTestConfig.usingGM {
	case true:
		fmt.Println("生成 SM2 key")
		k, err = provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
		// default:
		// 	fmt.Println("生成 ECDSA key")
		// 	k, err = provider.KeyGen(&bccsp.ECDSAKeyGenOpts{Temporary: false})
	}
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	// Export the public key
	pk, err := k.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting ECDSA public key [%s]", err)
	}

	pkRaw, err := pk.Bytes()
	if err != nil {
		t.Fatalf("Failed getting ECDSA raw public key [%s]", err)
	}

	pub, err := derToPublicKey(pkRaw)
	if err != nil {
		t.Fatalf("Failed converting raw to ecdsa.PublicKey [%s]", err)
	}

	var pk2 bccsp.Key
	switch currentTestConfig.usingGM {
	case true:
		fmt.Println("导入 SM2 key")
		pk2, err = provider.KeyImport(pub, &bccsp.SM2GoPublicKeyImportOpts{Temporary: false})
		// default:
		// 	fmt.Println("导入 ECDSA key")
		// 	pk2, err = provider.KeyImport(pub, &bccsp.ECDSAGoPublicKeyImportOpts{Temporary: false})
	}
	if err != nil {
		t.Fatalf("Failed importing ECDSA public key [%s]", err)
	}
	if pk2 == nil {
		t.Fatal("Failed importing ECDSA public key. Return BCCSP key cannot be nil.")
	}

	// Sign and verify with the imported public key
	msg := []byte("Hello World")

	var digest []byte
	switch currentTestConfig.usingGM {
	case true:
		fmt.Println("SM2 不需要预先对签名内容做摘要")
		digest = msg
		// default:
		// 	fmt.Println("ECDSA 需要预先对签名内容做摘要")
		// 	digest, err = provider.Hash(msg, &bccsp.SHAOpts{})
		// 	if err != nil {
		// 		t.Fatalf("Failed computing HASH [%s]", err)
		// 	}
	}

	signature, err := provider.Sign(k, digest, nil)
	if err != nil {
		t.Fatalf("Failed generating ECDSA signature [%s]", err)
	}

	valid, err := provider.Verify(pk2, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying ECDSA signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying ECDSA signature. Signature not valid.")
	}
}

// func TestECDSAKeyImportFromECDSAPrivateKey(t *testing.T) {
// 	t.Parallel()
// 	provider, _, cleanup := currentTestConfig.Provider(t)
// 	defer cleanup()

// 	// Generate an ECDSA key, default is P256
// 	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
// 	if err != nil {
// 		t.Fatalf("Failed generating ECDSA key [%s]", err)
// 	}

// 	// Import the ecdsa.PrivateKey
// 	priv, err := privateKeyToDER(key)
// 	if err != nil {
// 		t.Fatalf("Failed converting raw to ecdsa.PrivateKey [%s]", err)
// 	}

// 	sk, err := provider.KeyImport(priv, &bccsp.ECDSAPrivateKeyImportOpts{Temporary: false})
// 	if err != nil {
// 		t.Fatalf("Failed importing ECDSA private key [%s]", err)
// 	}
// 	if sk == nil {
// 		t.Fatal("Failed importing ECDSA private key. Return BCCSP key cannot be nil.")
// 	}

// 	// Import the ecdsa.PublicKey
// 	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
// 	if err != nil {
// 		t.Fatalf("Failed converting raw to ecdsa.PublicKey [%s]", err)
// 	}

// 	pk, err := provider.KeyImport(pub, &bccsp.ECDSAPKIXPublicKeyImportOpts{Temporary: false})

// 	if err != nil {
// 		t.Fatalf("Failed importing ECDSA public key [%s]", err)
// 	}
// 	if pk == nil {
// 		t.Fatal("Failed importing ECDSA public key. Return BCCSP key cannot be nil.")
// 	}

// 	// Sign and verify with the imported public key
// 	msg := []byte("Hello World")

// 	digest, err := provider.Hash(msg, &bccsp.SHAOpts{})
// 	if err != nil {
// 		t.Fatalf("Failed computing HASH [%s]", err)
// 	}

// 	signature, err := provider.Sign(sk, digest, nil)
// 	if err != nil {
// 		t.Fatalf("Failed generating ECDSA signature [%s]", err)
// 	}

// 	valid, err := provider.Verify(pk, signature, digest, nil)
// 	if err != nil {
// 		t.Fatalf("Failed verifying ECDSA signature [%s]", err)
// 	}
// 	if !valid {
// 		t.Fatal("Failed verifying ECDSA signature. Signature not valid.")
// 	}
// }

func TestKeyImportFromX509Sm2PublicKey(t *testing.T) {
	// func TestKeyImportFromX509ECDSAPublicKey(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	if !currentTestConfig.usingGM {
		return
	}

	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}

	// TODO 将x509改为 gmx509
	// Generate a self-signed certificate
	testExtKeyUsage := []gmx509.ExtKeyUsage{gmx509.ExtKeyUsageClientAuth, gmx509.ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	extraExtensionData := []byte("extra extension")
	commonName := "test.example.com"
	template := gmx509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
			// Organization: []string{"Σ Acme Co"},
			Organization: []string{"gcsoft"},
			Country:      []string{"CN"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{2, 5, 4, 42},
					Value: "zhaochun",
				},
				// This should override the Country, above.
				{
					Type:  []int{2, 5, 4, 6},
					Value: "CN",
				},
			},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(1 * time.Hour),

		SignatureAlgorithm: gmx509.SM2WithSM3,

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     gmx509.KeyUsageCertSign,

		ExtKeyUsage:        testExtKeyUsage,
		UnknownExtKeyUsage: testUnknownExtKeyUsage,

		BasicConstraintsValid: true,
		IsCA:                  true,

		OCSPServer:            []string{"http://ocurrentBCCSP.example.com"},
		IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},

		DNSNames:       []string{"test.example.com"},
		EmailAddresses: []string{"gopher@golang.org"},
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},

		PolicyIdentifiers:   []asn1.ObjectIdentifier{[]int{1, 2, 3}},
		PermittedDNSDomains: []string{".example.com", "example.com"},

		CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},

		ExtraExtensions: []pkix.Extension{
			{
				Id:    []int{1, 2, 3, 4},
				Value: extraExtensionData,
			},
		},
	}

	cryptoSigner, err := signer.New(provider, k)
	if err != nil {
		t.Fatalf("Failed initializing CyrptoSigner [%s]", err)
	}

	// x509证书持有者的公私钥获取，这里可以模拟使用ecdsa的公私钥。
	// 注释掉不使用 certKey 的话，则代表这个证书是持有者自签名的。
	// certKey, err := provider.KeyGen(&bccsp.ECDSAKeyGenOpts{Temporary: false})
	// if err != nil {
	// 	t.Fatalf("Failed generating ECDSA key [%s]", err)
	// }

	// Export the public key
	pk, err := k.PublicKey()
	// pk, err := certKey.PublicKey()
	if err != nil {
		t.Fatalf("Failed getting ECDSA public key [%s]", err)
	}

	pkRaw, err := pk.Bytes()
	if err != nil {
		t.Fatalf("Failed getting ECDSA raw public key [%s]", err)
	}

	pub, err := derToPublicKey(pkRaw)
	// pub, err := derToSm2PublicKey(pkRaw)
	if err != nil {
		t.Fatalf("Failed converting raw to ECDSA.PublicKey [%s]", err)
	}
	// gmx509只支持对 sm2公钥进行 签名
	certRaw, err := gmx509.CreateCertificate(rand.Reader, &template, &template, pub, cryptoSigner)
	// certRaw, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, cryptoSigner)
	if err != nil {
		t.Fatalf("Failed generating self-signed certificate [%s]", err)
	}

	cert, err := gmx509.ParseCertificate(certRaw)
	if err != nil {
		t.Fatalf("Failed generating X509 certificate object from raw [%s]", err)
	}

	// Import the certificate's public key
	pk2, err := provider.KeyImport(cert, &bccsp.GMX509PublicKeyImportOpts{Temporary: false})

	if err != nil {
		t.Fatalf("Failed importing ECDSA public key [%s]", err)
	}
	if pk2 == nil {
		t.Fatal("Failed importing ECDSA public key. Return BCCSP key cannot be nil.")
	}

	// Sign and verify with the imported public key
	msg := []byte("Hello World")

	digest, err := provider.Hash(msg, &bccsp.SM3Opts{})
	if err != nil {
		t.Fatalf("Failed computing HASH [%s]", err)
	}

	// 为了验证pk2是不是证书持有者的公钥，可以用证书持有者的私钥签名，
	// 然后用pk2验签。
	signature, err := provider.Sign(k, digest, nil)
	// signature, err := provider.Sign(certKey, digest, nil)
	if err != nil {
		t.Fatalf("Failed generating ECDSA signature [%s]", err)
	}

	valid, err := provider.Verify(pk2, signature, digest, nil)
	if err != nil {
		t.Fatalf("Failed verifying ECDSA signature [%s]", err)
	}
	if !valid {
		t.Fatal("Failed verifying ECDSA signature. Signature not valid.")
	}
	fmt.Println("TestKeyImportFromX509Sm2PublicKey 结束")
}

// func TestKeyImportFromX509ECDSAPublicKey(t *testing.T) {
// 	t.Parallel()
// 	provider, _, cleanup := currentTestConfig.Provider(t)
// 	defer cleanup()

// 	if currentTestConfig.usingGM {
// 		return
// 	}

// 	k, err := provider.KeyGen(&bccsp.ECDSAKeyGenOpts{Temporary: false})
// 	if err != nil {
// 		t.Fatalf("Failed generating ECDSA key [%s]", err)
// 	}

// 	// Generate a self-signed certificate
// 	testExtKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
// 	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
// 	extraExtensionData := []byte("extra extension")
// 	commonName := "test.example.com"
// 	template := x509.Certificate{
// 		SerialNumber: big.NewInt(1),
// 		Subject: pkix.Name{
// 			CommonName: commonName,
// 			// Organization: []string{"Σ Acme Co"},
// 			Organization: []string{"gcsoft"},
// 			Country:      []string{"CN"},
// 			ExtraNames: []pkix.AttributeTypeAndValue{
// 				{
// 					Type:  []int{2, 5, 4, 42},
// 					Value: "zhaochun",
// 				},
// 				// This should override the Country, above.
// 				{
// 					Type:  []int{2, 5, 4, 6},
// 					Value: "CN",
// 				},
// 			},
// 		},
// 		NotBefore: time.Now().Add(-1 * time.Hour),
// 		NotAfter:  time.Now().Add(1 * time.Hour),

// 		SignatureAlgorithm: x509.ECDSAWithSHA256,

// 		SubjectKeyId: []byte{1, 2, 3, 4},
// 		KeyUsage:     x509.KeyUsageCertSign,

// 		ExtKeyUsage:        testExtKeyUsage,
// 		UnknownExtKeyUsage: testUnknownExtKeyUsage,

// 		BasicConstraintsValid: true,
// 		IsCA:                  true,

// 		OCSPServer:            []string{"http://ocurrentBCCSP.example.com"},
// 		IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},

// 		DNSNames:       []string{"test.example.com"},
// 		EmailAddresses: []string{"gopher@golang.org"},
// 		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},

// 		PolicyIdentifiers:   []asn1.ObjectIdentifier{[]int{1, 2, 3}},
// 		PermittedDNSDomains: []string{".example.com", "example.com"},

// 		CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},

// 		ExtraExtensions: []pkix.Extension{
// 			{
// 				Id:    []int{1, 2, 3, 4},
// 				Value: extraExtensionData,
// 			},
// 		},
// 	}

// 	cryptoSigner, err := signer.New(provider, k)
// 	if err != nil {
// 		t.Fatalf("Failed initializing CyrptoSigner [%s]", err)
// 	}

// 	// Export the public key
// 	pk, err := k.PublicKey()
// 	// pk, err := certKey.PublicKey()
// 	if err != nil {
// 		t.Fatalf("Failed getting ECDSA public key [%s]", err)
// 	}

// 	pkRaw, err := pk.Bytes()
// 	if err != nil {
// 		t.Fatalf("Failed getting ECDSA raw public key [%s]", err)
// 	}

// 	pub, err := derToPublicKey(pkRaw)
// 	// pub, err := derToSm2PublicKey(pkRaw)
// 	if err != nil {
// 		t.Fatalf("Failed converting raw to ECDSA.PublicKey [%s]", err)
// 	}
// 	// gmx509只支持对 sm2公钥进行 签名
// 	certRaw, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, cryptoSigner)
// 	// certRaw, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, cryptoSigner)
// 	if err != nil {
// 		t.Fatalf("Failed generating self-signed certificate [%s]", err)
// 	}

// 	cert, err := x509.ParseCertificate(certRaw)
// 	if err != nil {
// 		t.Fatalf("Failed generating X509 certificate object from raw [%s]", err)
// 	}

// 	// Import the certificate's public key
// 	pk2, err := provider.KeyImport(cert, &bccsp.X509PublicKeyImportOpts{Temporary: false})

// 	if err != nil {
// 		t.Fatalf("Failed importing ECDSA public key [%s]", err)
// 	}
// 	if pk2 == nil {
// 		t.Fatal("Failed importing ECDSA public key. Return BCCSP key cannot be nil.")
// 	}

// 	// Sign and verify with the imported public key
// 	msg := []byte("Hello World")

// 	digest, err := provider.Hash(msg, &bccsp.SHAOpts{})
// 	if err != nil {
// 		t.Fatalf("Failed computing HASH [%s]", err)
// 	}

// 	// 为了验证pk2是不是证书持有者的公钥，可以用证书持有者的私钥签名，
// 	// 然后用pk2验签。
// 	signature, err := provider.Sign(k, digest, nil)
// 	// signature, err := provider.Sign(certKey, digest, nil)
// 	if err != nil {
// 		t.Fatalf("Failed generating ECDSA signature [%s]", err)
// 	}

// 	valid, err := provider.Verify(pk2, signature, digest, nil)
// 	if err != nil {
// 		t.Fatalf("Failed verifying ECDSA signature [%s]", err)
// 	}
// 	if !valid {
// 		t.Fatal("Failed verifying ECDSA signature. Signature not valid.")
// 	}
// 	fmt.Println("TestKeyImportFromX509ECDSAPublicKey 结束")
// }

// func TestECDSASignatureEncoding(t *testing.T) {
// 	t.Parallel()

// 	v := []byte{0x30, 0x07, 0x02, 0x01, 0x8F, 0x02, 0x02, 0xff, 0xf1}
// 	_, err := asn1.Unmarshal(v, &utils.ECDSASignature{})
// 	if err == nil {
// 		t.Fatalf("Unmarshalling should fail for [% x]", v)
// 	}
// 	t.Logf("Unmarshalling correctly failed for [% x] [%s]", v, err)

// 	v = []byte{0x30, 0x07, 0x02, 0x01, 0x8F, 0x02, 0x02, 0x00, 0x01}
// 	_, err = asn1.Unmarshal(v, &utils.ECDSASignature{})
// 	if err == nil {
// 		t.Fatalf("Unmarshalling should fail for [% x]", v)
// 	}
// 	t.Logf("Unmarshalling correctly failed for [% x] [%s]", v, err)

// 	v = []byte{0x30, 0x07, 0x02, 0x01, 0x8F, 0x02, 0x81, 0x01, 0x01}
// 	_, err = asn1.Unmarshal(v, &utils.ECDSASignature{})
// 	if err == nil {
// 		t.Fatalf("Unmarshalling should fail for [% x]", v)
// 	}
// 	t.Logf("Unmarshalling correctly failed for [% x] [%s]", v, err)

// 	v = []byte{0x30, 0x07, 0x02, 0x01, 0x8F, 0x02, 0x81, 0x01, 0x8F}
// 	_, err = asn1.Unmarshal(v, &utils.ECDSASignature{})
// 	if err == nil {
// 		t.Fatalf("Unmarshalling should fail for [% x]", v)
// 	}
// 	t.Logf("Unmarshalling correctly failed for [% x] [%s]", v, err)

// 	v = []byte{0x30, 0x0A, 0x02, 0x01, 0x8F, 0x02, 0x05, 0x00, 0x00, 0x00, 0x00, 0x8F}
// 	_, err = asn1.Unmarshal(v, &utils.ECDSASignature{})
// 	if err == nil {
// 		t.Fatalf("Unmarshalling should fail for [% x]", v)
// 	}
// 	t.Logf("Unmarshalling correctly failed for [% x] [%s]", v, err)

// }

// func TestECDSALowS(t *testing.T) {
// 	t.Parallel()
// 	provider, _, cleanup := currentTestConfig.Provider(t)
// 	defer cleanup()

// 	// Ensure that signature with low-S are generated
// 	k, err := provider.KeyGen(&bccsp.ECDSAKeyGenOpts{Temporary: false})
// 	if err != nil {
// 		t.Fatalf("Failed generating ECDSA key [%s]", err)
// 	}

// 	msg := []byte("Hello World")

// 	digest, err := provider.Hash(msg, &bccsp.SHAOpts{})
// 	if err != nil {
// 		t.Fatalf("Failed computing HASH [%s]", err)
// 	}

// 	signature, err := provider.Sign(k, digest, nil)
// 	if err != nil {
// 		t.Fatalf("Failed generating ECDSA signature [%s]", err)
// 	}

// 	_, S, err := utils.UnmarshalECDSASignature(signature)
// 	if err != nil {
// 		t.Fatalf("Failed unmarshalling signature [%s]", err)
// 	}

// 	if S.Cmp(utils.GetCurveHalfOrdersAt(k.(*ECDSAPrivateKey).privKey.Curve)) >= 0 {
// 		t.Fatal("Invalid signature. It must have low-S")
// 	}

// 	valid, err := provider.Verify(k, signature, digest, nil)
// 	if err != nil {
// 		t.Fatalf("Failed verifying ECDSA signature [%s]", err)
// 	}
// 	if !valid {
// 		t.Fatal("Failed verifying ECDSA signature. Signature not valid.")
// 	}

// 	// Ensure that signature with high-S are rejected.
// 	var R *big.Int
// 	// 不断签名，直到获取一个高S值的签名
// 	for {
// 		R, S, err = ecdsa.Sign(rand.Reader, k.(*ECDSAPrivateKey).privKey, digest)
// 		if err != nil {
// 			t.Fatalf("Failed generating signature [%s]", err)
// 		}

// 		if S.Cmp(utils.GetCurveHalfOrdersAt(k.(*ECDSAPrivateKey).privKey.Curve)) > 0 {
// 			break
// 		}
// 	}

// 	sig, err := utils.MarshalECDSASignature(R, S)
// 	if err != nil {
// 		t.Fatalf("Failing unmarshalling signature [%s]", err)
// 	}

// 	valid, err = provider.Verify(k, sig, digest, nil)
// 	// 高S值的签名必须验签失败
// 	if err == nil {
// 		t.Fatal("Failed verifying ECDSA signature. It must fail for a signature with high-S")
// 	}
// 	if valid {
// 		t.Fatal("Failed verifying ECDSA signature. It must fail for a signature with high-S")
// 	}
// }

// func TestAESKeyGen(t *testing.T) {
// 	t.Parallel()
// 	provider, _, cleanup := currentTestConfig.Provider(t)
// 	defer cleanup()

// 	k, err := provider.KeyGen(&bccsp.AESKeyGenOpts{Temporary: false})
// 	if err != nil {
// 		t.Fatalf("Failed generating AES_256 key [%s]", err)
// 	}
// 	if k == nil {
// 		t.Fatal("Failed generating AES_256 key. Key must be different from nil")
// 	}
// 	if !k.Private() {
// 		t.Fatal("Failed generating AES_256 key. Key should be private")
// 	}
// 	if !k.Symmetric() {
// 		t.Fatal("Failed generating AES_256 key. Key should be symmetric")
// 	}

// 	pk, err := k.PublicKey()
// 	if err == nil {
// 		t.Fatal("Error should be different from nil in this case")
// 	}
// 	if pk != nil {
// 		t.Fatal("Return value should be equal to nil in this case")
// 	}
// }

// func TestAESEncrypt(t *testing.T) {
// 	t.Parallel()
// 	provider, _, cleanup := currentTestConfig.Provider(t)
// 	defer cleanup()

// 	k, err := provider.KeyGen(&bccsp.AESKeyGenOpts{Temporary: false})
// 	if err != nil {
// 		t.Fatalf("Failed generating AES_256 key [%s]", err)
// 	}

// 	ct, err := provider.Encrypt(k, []byte("Hello World"), &bccsp.AESCBCPKCS7ModeOpts{})
// 	if err != nil {
// 		t.Fatalf("Failed encrypting [%s]", err)
// 	}
// 	if len(ct) == 0 {
// 		t.Fatal("Failed encrypting. Nil ciphertext")
// 	}
// }

// func TestAESDecrypt(t *testing.T) {
// 	t.Parallel()
// 	provider, _, cleanup := currentTestConfig.Provider(t)
// 	defer cleanup()

// 	k, err := provider.KeyGen(&bccsp.AESKeyGenOpts{Temporary: false})
// 	if err != nil {
// 		t.Fatalf("Failed generating AES_256 key [%s]", err)
// 	}

// 	msg := []byte("Hello World")

// 	ct, err := provider.Encrypt(k, msg, &bccsp.AESCBCPKCS7ModeOpts{})
// 	if err != nil {
// 		t.Fatalf("Failed encrypting [%s]", err)
// 	}

// 	pt, err := provider.Decrypt(k, ct, bccsp.AESCBCPKCS7ModeOpts{})
// 	if err != nil {
// 		t.Fatalf("Failed decrypting [%s]", err)
// 	}
// 	if len(ct) == 0 {
// 		t.Fatal("Failed decrypting. Nil plaintext")
// 	}

// 	if !bytes.Equal(msg, pt) {
// 		t.Fatalf("Failed decrypting. Decrypted plaintext is different from the original. [%x][%x]", msg, pt)
// 	}
// }

// func TestHMACTruncated256KeyDerivOverAES256Key(t *testing.T) {
// 	t.Parallel()
// 	provider, _, cleanup := currentTestConfig.Provider(t)
// 	defer cleanup()

// 	k, err := provider.KeyGen(&bccsp.AESKeyGenOpts{Temporary: false})
// 	if err != nil {
// 		t.Fatalf("Failed generating AES_256 key [%s]", err)
// 	}

// 	hmcaedKey, err := provider.KeyDeriv(k, &bccsp.HMACTruncated256AESDeriveKeyOpts{Temporary: false, Arg: []byte{1}})
// 	if err != nil {
// 		t.Fatalf("Failed HMACing AES_256 key [%s]", err)
// 	}
// 	if k == nil {
// 		t.Fatal("Failed HMACing AES_256 key. HMACed Key must be different from nil")
// 	}
// 	if !hmcaedKey.Private() {
// 		t.Fatal("Failed HMACing AES_256 key. HMACed Key should be private")
// 	}
// 	if !hmcaedKey.Symmetric() {
// 		t.Fatal("Failed HMACing AES_256 key. HMACed Key should be asymmetric")
// 	}
// 	raw, err := hmcaedKey.Bytes()
// 	if err == nil {
// 		t.Fatal("Failed marshalling to bytes. Operation must be forbidden")
// 	}
// 	if len(raw) != 0 {
// 		t.Fatal("Failed marshalling to bytes. Operation must return 0 bytes")
// 	}

// 	msg := []byte("Hello World")

// 	ct, err := provider.Encrypt(hmcaedKey, msg, &bccsp.AESCBCPKCS7ModeOpts{})
// 	if err != nil {
// 		t.Fatalf("Failed encrypting [%s]", err)
// 	}

// 	pt, err := provider.Decrypt(hmcaedKey, ct, bccsp.AESCBCPKCS7ModeOpts{})
// 	if err != nil {
// 		t.Fatalf("Failed decrypting [%s]", err)
// 	}
// 	if len(ct) == 0 {
// 		t.Fatal("Failed decrypting. Nil plaintext")
// 	}

// 	if !bytes.Equal(msg, pt) {
// 		t.Fatalf("Failed decrypting. Decrypted plaintext is different from the original. [%x][%x]", msg, pt)
// 	}
// }

// func TestHMACKeyDerivOverAES256Key(t *testing.T) {
// 	t.Parallel()
// 	provider, _, cleanup := currentTestConfig.Provider(t)
// 	defer cleanup()

// 	k, err := provider.KeyGen(&bccsp.AESKeyGenOpts{Temporary: false})
// 	if err != nil {
// 		t.Fatalf("Failed generating AES_256 key [%s]", err)
// 	}

// 	hmcaedKey, err := provider.KeyDeriv(k, &bccsp.HMACDeriveKeyOpts{Temporary: false, Arg: []byte{1}})

// 	if err != nil {
// 		t.Fatalf("Failed HMACing AES_256 key [%s]", err)
// 	}
// 	if k == nil {
// 		t.Fatal("Failed HMACing AES_256 key. HMACed Key must be different from nil")
// 	}
// 	if !hmcaedKey.Private() {
// 		t.Fatal("Failed HMACing AES_256 key. HMACed Key should be private")
// 	}
// 	if !hmcaedKey.Symmetric() {
// 		t.Fatal("Failed HMACing AES_256 key. HMACed Key should be asymmetric")
// 	}
// 	raw, err := hmcaedKey.Bytes()
// 	if err != nil {
// 		t.Fatalf("Failed marshalling to bytes [%s]", err)
// 	}
// 	if len(raw) == 0 {
// 		t.Fatal("Failed marshalling to bytes. 0 bytes")
// 	}
// }

// func TestAES256KeyImport(t *testing.T) {
// 	t.Parallel()
// 	provider, _, cleanup := currentTestConfig.Provider(t)
// 	defer cleanup()

// 	raw, err := GetRandomBytes(32)
// 	if err != nil {
// 		t.Fatalf("Failed generating AES key [%s]", err)
// 	}

// 	k, err := provider.KeyImport(raw, &bccsp.AES256ImportKeyOpts{Temporary: false})
// 	if err != nil {
// 		t.Fatalf("Failed importing AES_256 key [%s]", err)
// 	}
// 	if k == nil {
// 		t.Fatal("Failed importing AES_256 key. Imported Key must be different from nil")
// 	}
// 	if !k.Private() {
// 		t.Fatal("Failed HMACing AES_256 key. Imported Key should be private")
// 	}
// 	if !k.Symmetric() {
// 		t.Fatal("Failed HMACing AES_256 key. Imported Key should be asymmetric")
// 	}
// 	raw, err = k.Bytes()
// 	if err == nil {
// 		t.Fatal("Failed marshalling to bytes. Marshalling must fail.")
// 	}
// 	if len(raw) != 0 {
// 		t.Fatal("Failed marshalling to bytes. Output should be 0 bytes")
// 	}

// 	msg := []byte("Hello World")

// 	ct, err := provider.Encrypt(k, msg, &bccsp.AESCBCPKCS7ModeOpts{})
// 	if err != nil {
// 		t.Fatalf("Failed encrypting [%s]", err)
// 	}

// 	pt, err := provider.Decrypt(k, ct, bccsp.AESCBCPKCS7ModeOpts{})
// 	if err != nil {
// 		t.Fatalf("Failed decrypting [%s]", err)
// 	}
// 	if len(ct) == 0 {
// 		t.Fatal("Failed decrypting. Nil plaintext")
// 	}

// 	if !bytes.Equal(msg, pt) {
// 		t.Fatalf("Failed decrypting. Decrypted plaintext is different from the original. [%x][%x]", msg, pt)
// 	}
// }

// func TestAES256KeyImportBadPaths(t *testing.T) {
// 	t.Parallel()
// 	provider, _, cleanup := currentTestConfig.Provider(t)
// 	defer cleanup()

// 	_, err := provider.KeyImport(nil, &bccsp.AES256ImportKeyOpts{Temporary: false})
// 	if err == nil {
// 		t.Fatal("Failed importing key. Must fail on importing nil key")
// 	}

// 	_, err = provider.KeyImport([]byte{1}, &bccsp.AES256ImportKeyOpts{Temporary: false})
// 	if err == nil {
// 		t.Fatal("Failed importing key. Must fail on importing a key with an invalid length")
// 	}
// }

// func TestAES256KeyGenSKI(t *testing.T) {
// 	t.Parallel()
// 	provider, _, cleanup := currentTestConfig.Provider(t)
// 	defer cleanup()

// 	k, err := provider.KeyGen(&bccsp.AESKeyGenOpts{Temporary: false})
// 	if err != nil {
// 		t.Fatalf("Failed generating AES_256 key [%s]", err)
// 	}

// 	k2, err := provider.GetKey(k.SKI())
// 	if err != nil {
// 		t.Fatalf("Failed getting AES_256 key [%s]", err)
// 	}
// 	if k2 == nil {
// 		t.Fatal("Failed getting AES_256 key. Key must be different from nil")
// 	}
// 	if !k2.Private() {
// 		t.Fatal("Failed getting AES_256 key. Key should be private")
// 	}
// 	if !k2.Symmetric() {
// 		t.Fatal("Failed getting AES_256 key. Key should be symmetric")
// 	}

// 	// Check that the SKIs are the same
// 	if !bytes.Equal(k.SKI(), k2.SKI()) {
// 		t.Fatalf("SKIs are different [%x]!=[%x]", k.SKI(), k2.SKI())
// 	}
// }

// func TestSHA(t *testing.T) {
// 	t.Parallel()
// 	provider, _, cleanup := currentTestConfig.Provider(t)
// 	defer cleanup()

// 	for i := 0; i < 100; i++ {
// 		b, err := GetRandomBytes(i)
// 		if err != nil {
// 			t.Fatalf("Failed getting random bytes [%s]", err)
// 		}

// 		h1, err := provider.Hash(b, &bccsp.SHAOpts{})
// 		if err != nil {
// 			t.Fatalf("Failed computing SHA [%s]", err)
// 		}

// 		var h hash.Hash
// 		switch currentTestConfig.hashFamily {
// 		case "SHA2":
// 			switch currentTestConfig.securityLevel {
// 			case 256:
// 				h = sha256.New()
// 			case 384:
// 				h = sha512.New384()
// 			default:
// 				t.Fatalf("Invalid security level [%d]", currentTestConfig.securityLevel)
// 			}
// 		case "SHA3":
// 			switch currentTestConfig.securityLevel {
// 			case 256:
// 				h = sha3.New256()
// 			case 384:
// 				h = sha3.New384()
// 			default:
// 				t.Fatalf("Invalid security level [%d]", currentTestConfig.securityLevel)
// 			}
// 		case "SM3":
// 			h = sm3.New()
// 		default:
// 			t.Fatalf("Invalid hash family [%s]", currentTestConfig.hashFamily)
// 		}

// 		h.Write(b)
// 		h2 := h.Sum(nil)
// 		// fmt.Printf("h1 : %s \nh2 : %s \n", hex.EncodeToString(h1), hex.EncodeToString(h2))
// 		if !bytes.Equal(h1, h2) {
// 			t.Fatalf("Discrempancy found in HASH result [%x], [%x]!=[%x]", b, h1, h2)
// 		}
// 	}
// }

func TestAddWrapper(t *testing.T) {
	t.Parallel()
	p, _, cleanup := currentTestConfig.Provider(t)
	defer cleanup()

	sw, ok := p.(*CSP)
	assert.True(t, ok)

	tester := func(o interface{}, getter func(t reflect.Type) (interface{}, bool)) {
		tt := reflect.TypeOf(o)
		err := sw.AddWrapper(tt, o)
		assert.NoError(t, err)
		o2, ok := getter(tt)
		assert.True(t, ok)
		assert.Equal(t, o, o2)
	}

	tester(&mocks.KeyGenerator{}, func(t reflect.Type) (interface{}, bool) { o, ok := sw.KeyGenerators[t]; return o, ok })
	tester(&mocks.KeyDeriver{}, func(t reflect.Type) (interface{}, bool) { o, ok := sw.KeyDerivers[t]; return o, ok })
	tester(&mocks.KeyImporter{}, func(t reflect.Type) (interface{}, bool) { o, ok := sw.KeyImporters[t]; return o, ok })
	tester(&mocks.Encryptor{}, func(t reflect.Type) (interface{}, bool) { o, ok := sw.Encryptors[t]; return o, ok })
	tester(&mocks.Decryptor{}, func(t reflect.Type) (interface{}, bool) { o, ok := sw.Decryptors[t]; return o, ok })
	tester(&mocks.Signer{}, func(t reflect.Type) (interface{}, bool) { o, ok := sw.Signers[t]; return o, ok })
	tester(&mocks.Verifier{}, func(t reflect.Type) (interface{}, bool) { o, ok := sw.Verifiers[t]; return o, ok })
	tester(&mocks.Hasher{}, func(t reflect.Type) (interface{}, bool) { o, ok := sw.Hashers[t]; return o, ok })

	// Add invalid wrapper
	err := sw.AddWrapper(reflect.TypeOf(cleanup), cleanup)
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "wrapper type not valid, must be on of: KeyGenerator, KeyDeriver, KeyImporter, Encryptor, Decryptor, Signer, Verifier, Hasher")
}

// func getCryptoHashIndex(t *testing.T) crypto.Hash {
// 	switch currentTestConfig.hashFamily {
// 	case "SHA2":
// 		switch currentTestConfig.securityLevel {
// 		case 256:
// 			return crypto.SHA256
// 		case 384:
// 			return crypto.SHA384
// 		default:
// 			t.Fatalf("Invalid security level [%d]", currentTestConfig.securityLevel)
// 		}
// 	case "SHA3":
// 		switch currentTestConfig.securityLevel {
// 		case 256:
// 			return crypto.SHA3_256
// 		case 384:
// 			return crypto.SHA3_384
// 		default:
// 			t.Fatalf("Invalid security level [%d]", currentTestConfig.securityLevel)
// 		}
// 	default:
// 		t.Fatalf("Invalid hash family [%s]", currentTestConfig.hashFamily)
// 	}

// 	return crypto.SHA3_256
// }
