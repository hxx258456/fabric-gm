/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"

	"github.com/hxx258456/ccgo/sm2"
	"github.com/hxx258456/ccgo/x509"
)

// GenerateMockPublicPrivateKeyPairPEM returns public/private key pair encoded
// as PEM strings.
func GenerateMockPublicPrivateKeyPairPEM(isCA bool) (string, string, error) {
	// privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	privateKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	der, _ := x509.MarshalECPrivateKey(privateKey)
	privateKeyPEM := string(pem.EncodeToMemory(
		&pem.Block{
			Type:  "SM2 PRIVATE KEY",
			Bytes: der,
		},
	))

	template := x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject: pkix.Name{
			Organization: []string{"Hyperledger Fabric"},
		},
	}
	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	publicKeyCert, err := x509.CreateCertificate(rand.Reader, &template, &template, privateKey.Public(), privateKey)
	if err != nil {
		return "", "", err
	}

	publicKeyCertPEM := string(pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: publicKeyCert,
		},
	))

	return publicKeyCertPEM, privateKeyPEM, nil
}
