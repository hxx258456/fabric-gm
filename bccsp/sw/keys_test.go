/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/hxx258456/ccgo/sm2"
	"github.com/hxx258456/ccgo/x509"
	"github.com/stretchr/testify/assert"
)

// func TestOidFromNamedCurve(t *testing.T) {
// 	var (
// 		oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
// 		oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
// 		oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
// 		oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
// 	)

// 	type result struct {
// 		oid asn1.ObjectIdentifier
// 		ok  bool
// 	}

// 	var tests = []struct {
// 		name     string
// 		curve    elliptic.Curve
// 		expected result
// 	}{
// 		{
// 			name:  "P224",
// 			curve: elliptic.P224(),
// 			expected: result{
// 				oid: oidNamedCurveP224,
// 				ok:  true,
// 			},
// 		},
// 		{
// 			name:  "P256",
// 			curve: elliptic.P256(),
// 			expected: result{
// 				oid: oidNamedCurveP256,
// 				ok:  true,
// 			},
// 		},
// 		{
// 			name:  "P384",
// 			curve: elliptic.P384(),
// 			expected: result{
// 				oid: oidNamedCurveP384,
// 				ok:  true,
// 			},
// 		},
// 		{
// 			name:  "P521",
// 			curve: elliptic.P521(),
// 			expected: result{
// 				oid: oidNamedCurveP521,
// 				ok:  true,
// 			},
// 		},
// 		{
// 			name:  "T-1000",
// 			curve: &elliptic.CurveParams{Name: "T-1000"},
// 			expected: result{
// 				oid: nil,
// 				ok:  false,
// 			},
// 		},
// 	}

// 	for _, test := range tests {
// 		t.Run(test.name, func(t *testing.T) {
// 			oid, ok := oidFromNamedCurve(test.curve)
// 			assert.Equal(t, oid, test.expected.oid)
// 			assert.Equal(t, ok, test.expected.ok)
// 		})
// 	}

// }

func TestSM2Keys(t *testing.T) {
	// key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}

	// Private Key DER format
	der, err := privateKeyToDER(key)
	if err != nil {
		t.Fatalf("Failed converting private key to DER [%s]", err)
	}
	keyFromDER, err := derToPrivateKey(der)
	if err != nil {
		t.Fatalf("Failed converting DER to private key [%s]", err)
	}
	sm2KeyFromDer := keyFromDER.(*sm2.PrivateKey)
	// TODO: check the curve
	if key.D.Cmp(sm2KeyFromDer.D) != 0 {
		t.Fatal("Failed converting DER to private key. Invalid D.")
	}
	if key.X.Cmp(sm2KeyFromDer.X) != 0 {
		t.Fatal("Failed converting DER to private key. Invalid X coordinate.")
	}
	if key.Y.Cmp(sm2KeyFromDer.Y) != 0 {
		t.Fatal("Failed converting DER to private key. Invalid Y coordinate.")
	}

	// Private Key PEM format
	rawPEM, err := privateKeyToPEM(key, nil)
	if err != nil {
		t.Fatalf("Failed converting private key to PEM [%s]", err)
	}
	pemBlock, _ := pem.Decode(rawPEM)
	if pemBlock.Type != "PRIVATE KEY" {
		t.Fatalf("Expected type 'PRIVATE KEY' but found '%s'", pemBlock.Type)
	}
	// _, err = x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	_, err = x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse PKCS#8 private key [%s]", err)
	}
	keyFromPEM, err := pemToPrivateKey(rawPEM, nil)
	if err != nil {
		t.Fatalf("Failed converting DER to private key [%s]", err)
	}
	sm2KeyFromPEM := keyFromPEM.(*sm2.PrivateKey)
	// TODO: check the curve
	if key.D.Cmp(sm2KeyFromPEM.D) != 0 {
		t.Fatal("Failed converting PEM to private key. Invalid D.")
	}
	if key.X.Cmp(sm2KeyFromPEM.X) != 0 {
		t.Fatal("Failed converting PEM to private key. Invalid X coordinate.")
	}
	if key.Y.Cmp(sm2KeyFromPEM.Y) != 0 {
		t.Fatal("Failed converting PEM to private key. Invalid Y coordinate.")
	}

	// Nil Private Key <-> PEM
	_, err = privateKeyToPEM(nil, nil)
	if err == nil {
		t.Fatal("PublicKeyToPEM should fail on nil")
	}

	_, err = privateKeyToPEM((*sm2.PrivateKey)(nil), nil)
	if err == nil {
		t.Fatal("PrivateKeyToPEM should fail on nil")
	}

	_, err = pemToPrivateKey(nil, nil)
	if err == nil {
		t.Fatal("PEMtoPublicKey should fail on nil")
	}

	_, err = pemToPrivateKey([]byte{0, 1, 3, 4}, nil)
	if err == nil {
		t.Fatal("PEMtoPublicKey should fail invalid PEM")
	}

	_, err = derToPrivateKey(nil)
	if err == nil {
		t.Fatal("DERToPrivateKey should fail on nil")
	}

	_, err = derToPrivateKey([]byte{0, 1, 3, 4})
	if err == nil {
		t.Fatal("DERToPrivateKey should fail on invalid DER")
	}

	_, err = privateKeyToDER(nil)
	if err == nil {
		t.Fatal("DERToPrivateKey should fail on nil")
	}

	// Private Key Encrypted PEM format
	encPEM, err := privateKeyToPEM(key, []byte("passwd"))
	if err != nil {
		t.Fatalf("Failed converting private key to encrypted PEM [%s]", err)
	}
	_, err = pemToPrivateKey(encPEM, nil)
	assert.Error(t, err)
	encKeyFromPEM, err := pemToPrivateKey(encPEM, []byte("passwd"))
	if err != nil {
		t.Fatalf("Failed converting DER to private key [%s]", err)
	}
	ecdsaKeyFromEncPEM := encKeyFromPEM.(*sm2.PrivateKey)
	// TODO: check the curve
	if key.D.Cmp(ecdsaKeyFromEncPEM.D) != 0 {
		t.Fatal("Failed converting encrypted PEM to private key. Invalid D.")
	}
	if key.X.Cmp(ecdsaKeyFromEncPEM.X) != 0 {
		t.Fatal("Failed converting encrypted PEM to private key. Invalid X coordinate.")
	}
	if key.Y.Cmp(ecdsaKeyFromEncPEM.Y) != 0 {
		t.Fatal("Failed converting encrypted PEM to private key. Invalid Y coordinate.")
	}

	// Public Key PEM format
	rawPEM, err = publicKeyToPEM(&key.PublicKey, nil)
	if err != nil {
		t.Fatalf("Failed converting public key to PEM [%s]", err)
	}
	pemBlock, _ = pem.Decode(rawPEM)
	if pemBlock.Type != "PUBLIC KEY" {
		t.Fatalf("Expected type 'PUBLIC KEY' but found '%s'", pemBlock.Type)
	}
	keyFromPEM, err = pemToPublicKey(rawPEM, nil)
	if err != nil {
		t.Fatalf("Failed converting DER to public key [%s]", err)
	}
	ecdsaPkFromPEM := keyFromPEM.(*sm2.PublicKey)
	// TODO: check the curve
	if key.X.Cmp(ecdsaPkFromPEM.X) != 0 {
		t.Fatal("Failed converting PEM to private key. Invalid X coordinate.")
	}
	if key.Y.Cmp(ecdsaPkFromPEM.Y) != 0 {
		t.Fatal("Failed converting PEM to private key. Invalid Y coordinate.")
	}

	// Nil Public Key <-> PEM
	_, err = publicKeyToPEM(nil, nil)
	if err == nil {
		t.Fatal("PublicKeyToPEM should fail on nil")
	}

	_, err = pemToPublicKey(nil, nil)
	if err == nil {
		t.Fatal("PEMtoPublicKey should fail on nil")
	}

	_, err = pemToPublicKey([]byte{0, 1, 3, 4}, nil)
	if err == nil {
		t.Fatal("PEMtoPublicKey should fail on invalid PEM")
	}

	// Public Key Encrypted PEM format
	encPEM, err = publicKeyToPEM(&key.PublicKey, []byte("passwd"))
	if err != nil {
		t.Fatalf("Failed converting private key to encrypted PEM [%s]", err)
	}
	_, err = pemToPublicKey(encPEM, nil)
	assert.Error(t, err)
	pkFromEncPEM, err := pemToPublicKey(encPEM, []byte("passwd"))
	if err != nil {
		t.Fatalf("Failed converting DER to private key [%s]", err)
	}
	ecdsaPkFromEncPEM := pkFromEncPEM.(*sm2.PublicKey)
	// TODO: check the curve
	if key.X.Cmp(ecdsaPkFromEncPEM.X) != 0 {
		t.Fatal("Failed converting encrypted PEM to private key. Invalid X coordinate.")
	}
	if key.Y.Cmp(ecdsaPkFromEncPEM.Y) != 0 {
		t.Fatal("Failed converting encrypted PEM to private key. Invalid Y coordinate.")
	}

	_, err = pemToPublicKey(encPEM, []byte("passw"))
	if err == nil {
		t.Fatal("PEMtoPublicKey should fail on wrong password")
	}

	_, err = pemToPublicKey(encPEM, []byte("passw"))
	if err == nil {
		t.Fatal("PEMtoPublicKey should fail on nil password")
	}

	_, err = pemToPublicKey(nil, []byte("passwd"))
	if err == nil {
		t.Fatal("PEMtoPublicKey should fail on nil PEM")
	}

	_, err = pemToPublicKey([]byte{0, 1, 3, 4}, []byte("passwd"))
	if err == nil {
		t.Fatal("PEMtoPublicKey should fail on invalid PEM")
	}

	_, err = pemToPublicKey(nil, []byte("passw"))
	if err == nil {
		t.Fatal("PEMtoPublicKey should fail on nil PEM and wrong password")
	}

	// Public Key DER format
	der, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
	assert.NoError(t, err)
	keyFromDER, err = derToPublicKey(der)
	assert.NoError(t, err)
	ecdsaPkFromPEM = keyFromDER.(*sm2.PublicKey)
	// TODO: check the curve
	if key.X.Cmp(ecdsaPkFromPEM.X) != 0 {
		t.Fatal("Failed converting PEM to private key. Invalid X coordinate.")
	}
	if key.Y.Cmp(ecdsaPkFromPEM.Y) != 0 {
		t.Fatal("Failed converting PEM to private key. Invalid Y coordinate.")
	}
}

// func TestAESKey(t *testing.T) {
// 	k := []byte{0, 1, 2, 3, 4, 5}
// 	pem := aesToPEM(k)

// 	k2, err := pemToAES(pem, nil)
// 	assert.NoError(t, err)
// 	assert.Equal(t, k, k2)

// 	pem, err = aesToEncryptedPEM(k, k)
// 	assert.NoError(t, err)

// 	k2, err = pemToAES(pem, k)
// 	assert.NoError(t, err)
// 	assert.Equal(t, k, k2)

// 	_, err = pemToAES(pem, nil)
// 	assert.Error(t, err)

// 	_, err = aesToEncryptedPEM(k, nil)
// 	assert.NoError(t, err)

// 	k2, err = pemToAES(pem, k)
// 	assert.NoError(t, err)
// 	assert.Equal(t, k, k2)
// }

func TestSM4Key(t *testing.T) {
	k, _ := GetRandomBytes(16)
	fmt.Printf("生成随机sm4密钥: %v", k)

	pem := sm4ToPEM(k)

	k2, err := pemToSM4(pem, nil)
	assert.NoError(t, err)
	assert.Equal(t, k, k2)

	pem, err = sm4ToEncryptedPEM(k, k)
	assert.NoError(t, err)

	k2, err = pemToSM4(pem, k)
	assert.NoError(t, err)
	assert.Equal(t, k, k2)

	_, err = pemToSM4(pem, nil)
	assert.Error(t, err)

	_, err = sm4ToEncryptedPEM(k, nil)
	assert.NoError(t, err)

	k2, err = pemToSM4(pem, k)
	assert.NoError(t, err)
	assert.Equal(t, k, k2)
}

func TestDERToPublicKey(t *testing.T) {
	_, err := derToPublicKey(nil)
	assert.Error(t, err)
}

func TestNil(t *testing.T) {
	_, err := privateKeyToEncryptedPEM(nil, nil)
	assert.Error(t, err)

	_, err = privateKeyToEncryptedPEM((*sm2.PrivateKey)(nil), nil)
	assert.Error(t, err)

	_, err = privateKeyToEncryptedPEM("Hello World", nil)
	assert.Error(t, err)

	// _, err = pemToAES(nil, nil)
	// assert.Error(t, err)

	// _, err = aesToEncryptedPEM(nil, nil)
	// assert.Error(t, err)

	_, err = publicKeyToPEM(nil, nil)
	assert.Error(t, err)
	_, err = publicKeyToPEM((*sm2.PublicKey)(nil), nil)
	assert.Error(t, err)
	_, err = publicKeyToPEM(nil, []byte("hello world"))
	assert.Error(t, err)

	_, err = publicKeyToPEM("hello world", nil)
	assert.Error(t, err)
	_, err = publicKeyToPEM("hello world", []byte("hello world"))
	assert.Error(t, err)

	_, err = publicKeyToEncryptedPEM(nil, nil)
	assert.Error(t, err)
	_, err = publicKeyToEncryptedPEM((*sm2.PublicKey)(nil), nil)
	assert.Error(t, err)
	_, err = publicKeyToEncryptedPEM("hello world", nil)
	assert.Error(t, err)
	_, err = publicKeyToEncryptedPEM("hello world", []byte("Hello world"))
	assert.Error(t, err)
}
