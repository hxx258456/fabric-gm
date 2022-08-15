//go:build pkcs11
// +build pkcs11

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pkcs11

import (
	"testing"

	"github.com/hxx258456/ccgo/x509"
	"github.com/hxx258456/fabric-gm/bccsp"
	"github.com/stretchr/testify/assert"
)

func TestX509PublicKeyImportOptsKeyImporter(t *testing.T) {
	ki := currentBCCSP

	_, err := ki.KeyImport("Hello World", &bccsp.X509PublicKeyImportOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "[X509PublicKeyImportOpts] Invalid raw material. Expected *x509.Certificate")

	_, err = ki.KeyImport(nil, &bccsp.X509PublicKeyImportOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw. Cannot be nil")

	cert := &x509.Certificate{}
	cert.PublicKey = "Hello world"
	_, err = ki.KeyImport(cert, &bccsp.X509PublicKeyImportOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Certificate's public key type not recognized. Supported keys: [ECDSA]")
}
