/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package idemix

import (
	"reflect"

	"github.com/hxx258456/fabric-gm/bccsp/idemix/bridge"

	"github.com/hxx258456/fabric-gm/bccsp/idemix/handlers"

	"github.com/hxx258456/fabric-gm/bccsp"
	"github.com/hxx258456/fabric-gm/bccsp/sw"
	"github.com/pkg/errors"
)

/*
bccsp/idemix/bccsp.go 提供零知识证明所需的csp及其密码组件
*/

type csp struct {
	*sw.CSP
}

func New(keyStore bccsp.KeyStore) (*csp, error) {
	base, err := sw.New(keyStore)
	if err != nil {
		return nil, errors.Wrap(err, "failed instantiating base bccsp")
	}

	csp := &csp{CSP: base}

	// key generators
	// issuer使用FP256BN(基于 Weierstrass方程 的一种椭圆曲线)生成Issuer密钥(内部也有公私钥)
	base.AddWrapper(reflect.TypeOf(&bccsp.IdemixIssuerKeyGenOpts{}), &handlers.IssuerKeyGen{Issuer: &bridge.Issuer{NewRand: bridge.NewRandOrPanic}})
	// user使用FP256BN的随机数生成函数生成一个用户密钥
	base.AddWrapper(reflect.TypeOf(&bccsp.IdemixUserSecretKeyGenOpts{}), &handlers.UserKeyGen{User: &bridge.User{NewRand: bridge.NewRandOrPanic}})
	// 撤销公私钥直接使用了ecdsa，现在改为了sm2
	base.AddWrapper(reflect.TypeOf(&bccsp.IdemixRevocationKeyGenOpts{}), &handlers.RevocationKeyGen{Revocation: &bridge.Revocation{}})

	// key derivers
	// nymKey 由User密钥和Issuer公钥派生
	base.AddWrapper(reflect.TypeOf(handlers.NewUserSecretKey(nil, false)), &handlers.NymKeyDerivation{
		User: &bridge.User{NewRand: bridge.NewRandOrPanic},
	})

	// signers
	// user签名，使用的都是FP256BN
	base.AddWrapper(reflect.TypeOf(handlers.NewUserSecretKey(nil, false)), &userSecreKeySignerMultiplexer{
		signer:                  &handlers.Signer{SignatureScheme: &bridge.SignatureScheme{NewRand: bridge.NewRandOrPanic}},
		nymSigner:               &handlers.NymSigner{NymSignatureScheme: &bridge.NymSignatureScheme{NewRand: bridge.NewRandOrPanic}},
		credentialRequestSigner: &handlers.CredentialRequestSigner{CredRequest: &bridge.CredRequest{NewRand: bridge.NewRandOrPanic}},
	})
	// issuer签名，也用的FP256BN
	base.AddWrapper(reflect.TypeOf(handlers.NewIssuerSecretKey(nil, false)), &handlers.CredentialSigner{
		Credential: &bridge.Credential{NewRand: bridge.NewRandOrPanic},
	})
	// 撤销签名，本来是ecdsa，现在改为sm2
	base.AddWrapper(reflect.TypeOf(handlers.NewRevocationSecretKey(nil, false)), &handlers.CriSigner{
		Revocation: &bridge.Revocation{},
	})

	// verifiers
	base.AddWrapper(reflect.TypeOf(handlers.NewIssuerPublicKey(nil)), &issuerPublicKeyVerifierMultiplexer{
		verifier:                  &handlers.Verifier{SignatureScheme: &bridge.SignatureScheme{NewRand: bridge.NewRandOrPanic}},
		credentialRequestVerifier: &handlers.CredentialRequestVerifier{CredRequest: &bridge.CredRequest{NewRand: bridge.NewRandOrPanic}},
	})
	base.AddWrapper(reflect.TypeOf(handlers.NewNymPublicKey(nil)), &handlers.NymVerifier{
		NymSignatureScheme: &bridge.NymSignatureScheme{NewRand: bridge.NewRandOrPanic},
	})
	base.AddWrapper(reflect.TypeOf(handlers.NewUserSecretKey(nil, false)), &handlers.CredentialVerifier{
		Credential: &bridge.Credential{NewRand: bridge.NewRandOrPanic},
	})
	base.AddWrapper(reflect.TypeOf(handlers.NewRevocationPublicKey(nil)), &handlers.CriVerifier{
		Revocation: &bridge.Revocation{},
	})

	// importers
	base.AddWrapper(reflect.TypeOf(&bccsp.IdemixUserSecretKeyImportOpts{}), &handlers.UserKeyImporter{
		User: &bridge.User{},
	})
	base.AddWrapper(reflect.TypeOf(&bccsp.IdemixIssuerPublicKeyImportOpts{}), &handlers.IssuerPublicKeyImporter{
		Issuer: &bridge.Issuer{},
	})
	base.AddWrapper(reflect.TypeOf(&bccsp.IdemixNymPublicKeyImportOpts{}), &handlers.NymPublicKeyImporter{
		User: &bridge.User{},
	})
	base.AddWrapper(reflect.TypeOf(&bccsp.IdemixRevocationPublicKeyImportOpts{}), &handlers.RevocationPublicKeyImporter{})

	return csp, nil
}

// Sign signs digest using key k.
// The opts argument should be appropriate for the primitive used.
//
// Note that when a signature of a hash of a larger message is needed,
// the caller is responsible for hashing the larger message and passing
// the hash (as digest).
// Notice that this is overriding the Sign methods of the sw impl. to avoid the digest check.
func (csp *csp) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil.")
	}
	// Do not check for digest

	keyType := reflect.TypeOf(k)
	signer, found := csp.Signers[keyType]
	if !found {
		return nil, errors.Errorf("Unsupported 'SignKey' provided [%s]", keyType)
	}

	signature, err = signer.Sign(k, digest, opts)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed signing with opts [%v]", opts)
	}

	return
}

// Verify verifies signature against key k and digest
// Notice that this is overriding the Sign methods of the sw impl. to avoid the digest check.
func (csp *csp) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	// Validate arguments
	if k == nil {
		return false, errors.New("Invalid Key. It must not be nil.")
	}
	if len(signature) == 0 {
		return false, errors.New("Invalid signature. Cannot be empty.")
	}
	// Do not check for digest

	verifier, found := csp.Verifiers[reflect.TypeOf(k)]
	if !found {
		return false, errors.Errorf("Unsupported 'VerifyKey' provided [%v]", k)
	}

	valid, err = verifier.Verify(k, signature, digest, opts)
	if err != nil {
		return false, errors.Wrapf(err, "Failed verifing with opts [%v]", opts)
	}

	return
}

type userSecreKeySignerMultiplexer struct {
	signer                  *handlers.Signer
	nymSigner               *handlers.NymSigner
	credentialRequestSigner *handlers.CredentialRequestSigner
}

func (s *userSecreKeySignerMultiplexer) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	switch opts.(type) {
	case *bccsp.IdemixSignerOpts:
		return s.signer.Sign(k, digest, opts)
	case *bccsp.IdemixNymSignerOpts:
		return s.nymSigner.Sign(k, digest, opts)
	case *bccsp.IdemixCredentialRequestSignerOpts:
		return s.credentialRequestSigner.Sign(k, digest, opts)
	default:
		return nil, errors.New("invalid opts, expected *bccsp.IdemixSignerOpt or *bccsp.IdemixNymSignerOpts or *bccsp.IdemixCredentialRequestSignerOpts")
	}
}

type issuerPublicKeyVerifierMultiplexer struct {
	verifier                  *handlers.Verifier
	credentialRequestVerifier *handlers.CredentialRequestVerifier
}

func (v *issuerPublicKeyVerifierMultiplexer) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	switch opts.(type) {
	case *bccsp.IdemixSignerOpts:
		return v.verifier.Verify(k, signature, digest, opts)
	case *bccsp.IdemixCredentialRequestSignerOpts:
		return v.credentialRequestVerifier.Verify(k, signature, digest, opts)
	default:
		return false, errors.New("invalid opts, expected *bccsp.IdemixSignerOpts or *bccsp.IdemixCredentialRequestSignerOpts")
	}
}
