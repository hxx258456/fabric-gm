/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bccsp

import "io"

/*
 * bccsp/opts.go 实现部分`bccsp.KeyGenOpts`、`bccsp.KeyImportOpts`与`bccsp.KeyDerivOpts`接口。
 * ecdsa相关: ECDSAKeyGenOpts, ECDSAPrivateKeyImportOpts, ECDSAPKIXPublicKeyImportOpts, ECDSAGoPublicKeyImportOpts, ECDSAReRandKeyOpts
 * sm2相关: SM2KeyGenOpts, SM2PrivateKeyImportOpts, SM2PublicKeyImportOpts
 * sm4相关: SM4KeyGenOpts, SM4ImportKeyOpts
 * aes相关: AESKeyGenOpts, AES256ImportKeyOpts
 * hmac相关: HMACTruncated256AESDeriveKeyOpts, HMACDeriveKeyOpts, HMACImportKeyOpts
 * sha相关: SHAOpts
 * x509相关: X509PublicKeyImportOpts
 */

const (
	// // ECDSA Elliptic Curve Digital Signature Algorithm (key gen, import, sign, verify),
	// // at default security level.
	// // Each BCCSP may or may not support default security level. If not supported than
	// // an error will be returned.
	// ECDSA = "ECDSA"

	// // ECDSA Elliptic Curve Digital Signature Algorithm over P-256 curve
	// ECDSAP256 = "ECDSAP256"

	// // ECDSA Elliptic Curve Digital Signature Algorithm over P-384 curve
	// ECDSAP384 = "ECDSAP384"

	// // ECDSAReRand ECDSA key re-randomization
	// ECDSAReRand = "ECDSA_RERAND"

	// // AES Advanced Encryption Standard at the default security level.
	// // Each BCCSP may or may not support default security level. If not supported than
	// // an error will be returned.
	// AES = "AES"
	// // AES Advanced Encryption Standard at 128 bit security level
	// AES128 = "AES128"
	// // AES Advanced Encryption Standard at 192 bit security level
	// AES192 = "AES192"
	// // AES Advanced Encryption Standard at 256 bit security level
	// AES256 = "AES256"

	// // HMAC keyed-hash message authentication code
	// HMAC = "HMAC"
	// // HMACTruncated256 HMAC truncated at 256 bits.
	// HMACTruncated256 = "HMAC_TRUNCATED_256"

	// // SHA Secure Hash Algorithm using default family.
	// // Each BCCSP may or may not support default security level. If not supported than
	// // an error will be returned.
	// SHA = "SHA"

	// // SHA2 is an identifier for SHA2 hash family
	// SHA2 = "SHA2"
	// // SHA3 is an identifier for SHA3 hash family
	// SHA3 = "SHA3"

	// // SHA256
	// SHA256 = "SHA256"
	// // SHA384
	// SHA384 = "SHA384"
	// // SHA3_256
	// SHA3_256 = "SHA3_256"
	// // SHA3_384
	// SHA3_384 = "SHA3_384"

	// // X509Certificate Label for X509 certificate related operation
	// X509Certificate = "X509Certificate"
	// GMX509Certificate
	GMX509Certificate = "GMX509Certificate"
	// SM4
	SM4 = "SM4"
	// SM3
	SM3 = "SM3"
	// SM2
	SM2 = "SM2"
)

// // 定义 ECDSAKeyGenOpts 并为其实现`bccsp.KeyGenOpts`接口
// // ECDSAKeyGenOpts contains options for ECDSA key generation.
// type ECDSAKeyGenOpts struct {
// 	Temporary bool
// }

// // Algorithm returns the key generation algorithm identifier (to be used).
// func (opts *ECDSAKeyGenOpts) Algorithm() string {
// 	return ECDSA
// }

// // Ephemeral returns true if the key to generate has to be ephemeral,
// // false otherwise.
// func (opts *ECDSAKeyGenOpts) Ephemeral() bool {
// 	return opts.Temporary
// }

// // 定义 ECDSAPKIXPublicKeyImportOpts 并为其实现`bccsp.KeyImportOpts`接口
// // ECDSAPKIXPublicKeyImportOpts contains options for ECDSA public key importation in PKIX format
// type ECDSAPKIXPublicKeyImportOpts struct {
// 	Temporary bool
// }

// // Algorithm returns the key importation algorithm identifier (to be used).
// func (opts *ECDSAPKIXPublicKeyImportOpts) Algorithm() string {
// 	return ECDSA
// }

// // Ephemeral returns true if the key to generate has to be ephemeral,
// // false otherwise.
// func (opts *ECDSAPKIXPublicKeyImportOpts) Ephemeral() bool {
// 	return opts.Temporary
// }

// // 定义 ECDSAPrivateKeyImportOpts 并为其实现`bccsp.KeyImportOpts`接口
// // ECDSAPrivateKeyImportOpts contains options for ECDSA secret key importation in DER format
// // or PKCS#8 format.
// type ECDSAPrivateKeyImportOpts struct {
// 	Temporary bool
// }

// // Algorithm returns the key importation algorithm identifier (to be used).
// func (opts *ECDSAPrivateKeyImportOpts) Algorithm() string {
// 	return ECDSA
// }

// // Ephemeral returns true if the key to generate has to be ephemeral,
// // false otherwise.
// func (opts *ECDSAPrivateKeyImportOpts) Ephemeral() bool {
// 	return opts.Temporary
// }

// // 定义 ECDSAGoPublicKeyImportOpts 并为其实现 `bccsp.KeyImportOpts`接口
// // ECDSAGoPublicKeyImportOpts contains options for ECDSA key importation from ecdsa.PublicKey
// type ECDSAGoPublicKeyImportOpts struct {
// 	Temporary bool
// }

// // Algorithm returns the key importation algorithm identifier (to be used).
// func (opts *ECDSAGoPublicKeyImportOpts) Algorithm() string {
// 	return ECDSA
// }

// // Ephemeral returns true if the key to generate has to be ephemeral,
// // false otherwise.
// func (opts *ECDSAGoPublicKeyImportOpts) Ephemeral() bool {
// 	return opts.Temporary
// }

// // 定义 ECDSAReRandKeyOpts 似乎没有对应接口。。。
// // ECDSAReRandKeyOpts contains options for ECDSA key re-randomization.
// type ECDSAReRandKeyOpts struct {
// 	Temporary bool
// 	Expansion []byte
// }

// // Algorithm returns the key derivation algorithm identifier (to be used).
// func (opts *ECDSAReRandKeyOpts) Algorithm() string {
// 	return ECDSAReRand
// }

// // Ephemeral returns true if the key to generate has to be ephemeral,
// // false otherwise.
// func (opts *ECDSAReRandKeyOpts) Ephemeral() bool {
// 	return opts.Temporary
// }

// // ExpansionValue returns the re-randomization factor
// func (opts *ECDSAReRandKeyOpts) ExpansionValue() []byte {
// 	return opts.Expansion
// }

// // 定义 AESKeyGenOpts 并为其实现`bccsp.KeyGenOpts`接口
// // AESKeyGenOpts contains options for AES key generation at default security level
// type AESKeyGenOpts struct {
// 	Temporary bool
// }

// // Algorithm returns the key generation algorithm identifier (to be used).
// func (opts *AESKeyGenOpts) Algorithm() string {
// 	return AES
// }

// // Ephemeral returns true if the key to generate has to be ephemeral,
// // false otherwise.
// func (opts *AESKeyGenOpts) Ephemeral() bool {
// 	return opts.Temporary
// }

// // HMACTruncated256AESDeriveKeyOpts contains options for HMAC truncated
// // at 256 bits key derivation.
// type HMACTruncated256AESDeriveKeyOpts struct {
// 	Temporary bool
// 	Arg       []byte
// }

// // Algorithm returns the key derivation algorithm identifier (to be used).
// func (opts *HMACTruncated256AESDeriveKeyOpts) Algorithm() string {
// 	return HMACTruncated256
// }

// // Ephemeral returns true if the key to generate has to be ephemeral,
// // false otherwise.
// func (opts *HMACTruncated256AESDeriveKeyOpts) Ephemeral() bool {
// 	return opts.Temporary
// }

// // Argument returns the argument to be passed to the HMAC
// func (opts *HMACTruncated256AESDeriveKeyOpts) Argument() []byte {
// 	return opts.Arg
// }

// // HMACDeriveKeyOpts contains options for HMAC key derivation.
// type HMACDeriveKeyOpts struct {
// 	Temporary bool
// 	Arg       []byte
// }

// // Algorithm returns the key derivation algorithm identifier (to be used).
// func (opts *HMACDeriveKeyOpts) Algorithm() string {
// 	return HMAC
// }

// // Ephemeral returns true if the key to generate has to be ephemeral,
// // false otherwise.
// func (opts *HMACDeriveKeyOpts) Ephemeral() bool {
// 	return opts.Temporary
// }

// // Argument returns the argument to be passed to the HMAC
// func (opts *HMACDeriveKeyOpts) Argument() []byte {
// 	return opts.Arg
// }

// // AES256ImportKeyOpts contains options for importing AES 256 keys.
// type AES256ImportKeyOpts struct {
// 	Temporary bool
// }

// // Algorithm returns the key importation algorithm identifier (to be used).
// func (opts *AES256ImportKeyOpts) Algorithm() string {
// 	return AES
// }

// // Ephemeral returns true if the key generated has to be ephemeral,
// // false otherwise.
// func (opts *AES256ImportKeyOpts) Ephemeral() bool {
// 	return opts.Temporary
// }

// // HMACImportKeyOpts contains options for importing HMAC keys.
// type HMACImportKeyOpts struct {
// 	Temporary bool
// }

// // Algorithm returns the key importation algorithm identifier (to be used).
// func (opts *HMACImportKeyOpts) Algorithm() string {
// 	return HMAC
// }

// // Ephemeral returns true if the key generated has to be ephemeral,
// // false otherwise.
// func (opts *HMACImportKeyOpts) Ephemeral() bool {
// 	return opts.Temporary
// }

// // GMHMACImportKeyOpts contains options for importing HMAC keys.
// type GMHMACImportKeyOpts struct {
// 	Temporary bool
// }

// // Algorithm returns the key importation algorithm identifier (to be used).
// func (opts *GMHMACImportKeyOpts) Algorithm() string {
// 	return HMAC
// }

// // Ephemeral returns true if the key generated has to be ephemeral,
// // false otherwise.
// func (opts *GMHMACImportKeyOpts) Ephemeral() bool {
// 	return opts.Temporary
// }

// // SHAOpts contains options for computing SHA.
// type SHAOpts struct{}

// // Algorithm returns the hash algorithm identifier (to be used).
// func (opts *SHAOpts) Algorithm() string {
// 	return SHA
// }

// // X509PublicKeyImportOpts contains options for importing public keys from an x509 certificate
// type X509PublicKeyImportOpts struct {
// 	Temporary bool
// }

// // Algorithm returns the key importation algorithm identifier (to be used).
// func (opts *X509PublicKeyImportOpts) Algorithm() string {
// 	return X509Certificate
// }

// // Ephemeral returns true if the key to generate has to be ephemeral,
// // false otherwise.
// func (opts *X509PublicKeyImportOpts) Ephemeral() bool {
// 	return opts.Temporary
// }

// GMX509PublicKeyImportOpts contains options for importing public keys from an gmx509 certificate
type GMX509PublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *GMX509PublicKeyImportOpts) Algorithm() string {
	return GMX509Certificate
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *GMX509PublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

// SM2KeyGenOpts contains options for SM2 key generation.
type SM2KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *SM2KeyGenOpts) Algorithm() string {
	return SM2
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SM2KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

// SM4KeyGenOpts contains options for SM2 key generation.
type SM4KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *SM4KeyGenOpts) Algorithm() string {
	return SM4
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SM4KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

//SM4ImportKeyOpts  实现  bccsp.KeyImportOpts 接口
type SM4ImportKeyOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *SM4ImportKeyOpts) Algorithm() string {
	return SM4
}

// Ephemeral returns true if the key generated has to be ephemeral,
// false otherwise.
func (opts *SM4ImportKeyOpts) Ephemeral() bool {
	return opts.Temporary
}

type SM4EncrypterDecrypterOpts struct {
	// 初始偏移量 在 CBC, CFB, OFB 分组模式下需要
	IV []byte
	// PRNG is an instance of a PRNG to be used by the underlying cipher.
	// It is used only if different from nil.
	PRNG io.Reader
}

//SM2PrivateKeyImportOpts  实现  bccsp.KeyImportOpts 接口
type SM2PrivateKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *SM2PrivateKeyImportOpts) Algorithm() string {
	return SM2
}

// Ephemeral returns true if the key generated has to be ephemeral,
// false otherwise.
func (opts *SM2PrivateKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

//SM2PublicKeyImportOpts  实现  bccsp.KeyImportOpts 接口
type SM2PublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *SM2PublicKeyImportOpts) Algorithm() string {
	return SM2
}

// Ephemeral returns true if the key generated has to be ephemeral,
// false otherwise.
func (opts *SM2PublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

//SM2GoPublicKeyImportOpts  实现  bccsp.KeyImportOpts 接口
type SM2GoPublicKeyImportOpts struct {
	Temporary bool
}

// Algorithm returns the key importation algorithm identifier (to be used).
func (opts *SM2GoPublicKeyImportOpts) Algorithm() string {
	return SM2
}

// Ephemeral returns true if the key generated has to be ephemeral,
// false otherwise.
func (opts *SM2GoPublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}
