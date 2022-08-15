/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/hxx258456/ccgo/sm2"
	gmx509 "github.com/hxx258456/ccgo/x509"
)

/*
bccsp/sw/keys.go 定义PKCS#8标准结构体与椭圆曲线私钥结构体，并提供它们之间相互转换的函数。
但这些函数并未公开，只能在包内部调用。
*/

// type pkcs8Info struct {
// 	Version             int
// 	PrivateKeyAlgorithm []asn1.ObjectIdentifier
// 	PrivateKey          []byte
// }

// type ecPrivateKey struct {
// 	Version       int
// 	PrivateKey    []byte
// 	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
// 	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
// }

// var (
// 	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
// 	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
// 	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
// 	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
// 	// SM2椭圆曲线参数标识 没有查到，用SM2算法标识代替
// 	oidNamedCurveP256SM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}
// )

// var oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

// func oidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) {
// 	switch curve {
// 	case elliptic.P224():
// 		return oidNamedCurveP224, true
// 	case elliptic.P256():
// 		return oidNamedCurveP256, true
// 	case elliptic.P384():
// 		return oidNamedCurveP384, true
// 	case elliptic.P521():
// 		return oidNamedCurveP521, true
// 	case sm2.P256Sm2():
// 		return oidNamedCurveP256SM2, true
// 	}
// 	return nil, false
// }

// func privateKeyToDER(privateKey *ecdsa.PrivateKey) ([]byte, error) {
// 	if privateKey == nil {
// 		return nil, errors.New("invalid ecdsa private key. It must be different from nil")
// 	}

// 	return x509.MarshalECPrivateKey(privateKey)
// }

// 将私钥转为der字节流
//  - privateKey : *sm2.PrivateKey
func privateKeyToDER(privateKey interface{}) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("invalid private key. It must be different from nil")
	}

	switch k := privateKey.(type) {
	case *sm2.PrivateKey:
		return gmx509.MarshalECPrivateKey(k)
	// case *ecdsa.PrivateKey:
	// 	return x509.MarshalECPrivateKey(k)
	default:
		return nil, errors.New("invalid key type. It must be *sm2.PrivateKey")
	}
}

// privateKeyToPEM converts the private key to PEM format.
// EC private keys are converted to PKCS#8 format.
// 国密对应后只支持sm2，将私钥转为pkcs8格式字节流，根据pwd是否为空决定是否加密，然后包装为pem字节流
func privateKeyToPEM(privateKey interface{}, pwd []byte) ([]byte, error) {
	// Validate inputs
	if len(pwd) != 0 {
		return privateKeyToEncryptedPEM(privateKey, pwd)
	}
	if privateKey == nil {
		return nil, errors.New("invalid key. It must be different from nil")
	}

	switch k := privateKey.(type) {
	// case *ecdsa.PrivateKey:
	// 	if k == nil {
	// 		return nil, errors.New("invalid ecdsa private key. It must be different from nil")
	// 	}

	// 	// get the oid for the curve
	// 	oidNamedCurve, ok := oidFromNamedCurve(k.Curve)
	// 	if !ok {
	// 		return nil, errors.New("unknown elliptic curve")
	// 	}

	// 	// based on https://golang.org/src/crypto/x509/sec1.go
	// 	privateKeyBytes := k.D.Bytes()
	// 	paddedPrivateKey := make([]byte, (k.Curve.Params().N.BitLen()+7)/8)
	// 	copy(paddedPrivateKey[len(paddedPrivateKey)-len(privateKeyBytes):], privateKeyBytes)
	// 	// omit NamedCurveOID for compatibility as it's optional
	// 	asn1Bytes, err := asn1.Marshal(ecPrivateKey{
	// 		Version:    1,
	// 		PrivateKey: paddedPrivateKey,
	// 		PublicKey:  asn1.BitString{Bytes: elliptic.Marshal(k.Curve, k.X, k.Y)},
	// 	})

	// 	if err != nil {
	// 		return nil, fmt.Errorf("error marshaling EC key to asn1: [%s]", err)
	// 	}

	// 	var pkcs8Key pkcs8Info
	// 	pkcs8Key.Version = 0
	// 	pkcs8Key.PrivateKeyAlgorithm = make([]asn1.ObjectIdentifier, 2)
	// 	pkcs8Key.PrivateKeyAlgorithm[0] = oidPublicKeyECDSA
	// 	pkcs8Key.PrivateKeyAlgorithm[1] = oidNamedCurve
	// 	pkcs8Key.PrivateKey = asn1Bytes

	// 	pkcs8Bytes, err := asn1.Marshal(pkcs8Key)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("error marshaling EC key to asn1: [%s]", err)
	// 	}
	// 	return pem.EncodeToMemory(
	// 		&pem.Block{
	// 			Type:  "PRIVATE KEY",
	// 			Bytes: pkcs8Bytes,
	// 		},
	// 	), nil
	// case *rsa.PrivateKey:
	// 	if k == nil {
	// 		return nil, errors.New("invalid rsa private key. It must be different from nil")
	// 	}
	// 	raw := x509.MarshalPKCS1PrivateKey(k)

	// 	return pem.EncodeToMemory(
	// 		&pem.Block{
	// 			Type:  "RSA PRIVATE KEY",
	// 			Bytes: raw,
	// 		},
	// 	), nil
	case *sm2.PrivateKey:
		if k == nil {
			return nil, errors.New("invalid sm2 private key. It must be different from nil")
		}
		return gmx509.WritePrivateKeyToPem(k, nil)
	default:
		return nil, errors.New("invalid key type. It must be *sm2.PrivateKey")
	}
}

// privateKeyToEncryptedPEM converts a private key to an encrypted PEM
// 国密对应后只支持sm2，将私钥转为pkcs8格式字节流，根据pwd是否为空决定是否加密，然后包装为pem字节流
func privateKeyToEncryptedPEM(privateKey interface{}, pwd []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("invalid private key. It must be different from nil")
	}

	switch k := privateKey.(type) {
	// case *ecdsa.PrivateKey:
	// 	if k == nil {
	// 		return nil, errors.New("invalid ecdsa private key. It must be different from nil")
	// 	}
	// 	raw, err := x509.MarshalECPrivateKey(k)

	// 	if err != nil {
	// 		return nil, err
	// 	}

	// 	block, err := gmx509.EncryptPEMBlock(
	// 		rand.Reader,
	// 		"PRIVATE KEY",
	// 		raw,
	// 		pwd,
	// 		gmx509.PEMCipherAES256)

	// 	if err != nil {
	// 		return nil, err
	// 	}

	// 	return pem.EncodeToMemory(block), nil
	case *sm2.PrivateKey:
		if k == nil {
			return nil, errors.New("invalid sm2 private key. It must be different from nil")
		}
		return gmx509.WritePrivateKeyToPem(k, pwd)
	default:
		return nil, errors.New("invalid key type. It must be *sm2.PrivateKey")
	}
}

// 将der字节流转为私钥
// 依次尝试转换为 sm2, ecdsa, rsa 的私钥
func derToPrivateKey(der []byte) (key interface{}, err error) {
	if key, err = gmx509.ParsePKCS8PrivateKey(der); err == nil {
		switch key.(type) {
		case *sm2.PrivateKey:
			return
		default:
			return nil, errors.New("found private key type not sm2 in PKCS#8 wrapping")
		}
	}
	if key, err = gmx509.ParseECPrivateKey(der); err == nil {
		return
	}
	if key, err = gmx509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("invalid key type. The DER must contain an sm2.PrivateKey")
}

// 将der字节流转为sm2私钥
func derToSm2Priv(der []byte) (*sm2.PrivateKey, error) {
	keyRaw, err := gmx509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	key, ok := keyRaw.(*sm2.PrivateKey)
	if !ok {
		return nil, errors.New("bccsp/sw/keys.go derToSm2Priv : der is not sm2 privatekey")
	}
	return key, nil
}

// // 将der字节流转为ecdsa私钥
// func derToEcdsaPriv(der []byte) (*ecdsa.PrivateKey, error) {
// 	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
// 		switch key := key.(type) {
// 		case *ecdsa.PrivateKey:
// 			return key, err
// 		default:
// 			return nil, errors.New("found unknown private key type in PKCS#8 wrapping")
// 		}
// 	}

// 	if key, err := x509.ParseECPrivateKey(der); err == nil {
// 		return key, err
// 	}
// 	return nil, errors.New("invalid key type. The DER must contain an ecdsa.PrivateKey")
// }

// 将pem字节流转为私钥
// 依次尝试 sm2, rsa, ecdsa
func pemToPrivateKey(raw []byte, pwd []byte) (interface{}, error) {
	if len(raw) == 0 {
		return nil, errors.New("invalid PEM. It must be different from nil")
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("failed decoding PEM. Block must be different from nil. [% x]", raw)
	}

	// derive from header the type of the key
	if gmx509.IsEncryptedPEMBlock(block) {
		if len(pwd) == 0 {
			return nil, errors.New("encrypted Key. Need a password")
		}
		decrypted, err := gmx509.DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, fmt.Errorf("failed PEM decryption: [%s]", err)
		}

		key, err := derToPrivateKey(decrypted)
		if err != nil {
			return nil, err
		}
		return key, err
	}

	privKey, err := derToPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return privKey, err
}

// 将pem字节流转为sm2私钥
func pemToSm2PrivateKey(raw []byte, pwd []byte) (*sm2.PrivateKey, error) {
	privKey, err := pemToPrivateKey(raw, pwd)
	if err != nil {
		return nil, err
	}
	key, ok := privKey.(*sm2.PrivateKey)
	if !ok {
		return nil, errors.New("bccsp/sw/keys.go pemToSm2PrivateKey : pem is not sm2 privatekey")
	}
	return key, nil
}

// // 将pem字节流转为ecdsa私钥
// func pemToEcdsaPrivateKey(raw []byte, pwd []byte) (*ecdsa.PrivateKey, error) {
// 	block, _ := pem.Decode(raw)
// 	if block == nil {
// 		return nil, fmt.Errorf("failed decoding PEM. Block must be different from nil [% x]", raw)
// 	}

// 	// derive from header the type of the key
// 	if gmx509.IsEncryptedPEMBlock(block) {
// 		if len(pwd) == 0 {
// 			return nil, errors.New("encrypted Key. Need a password")
// 		}
// 		decrypted, err := gmx509.DecryptPEMBlock(block, pwd)
// 		if err != nil {
// 			return nil, fmt.Errorf("failed PEM decryption: [%s]", err)
// 		}

// 		key, err := derToEcdsaPriv(decrypted)
// 		if err != nil {
// 			return nil, err
// 		}
// 		return key, err
// 	}

// 	cert, err := derToEcdsaPriv(block.Bytes)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return cert, err
// }

// 将pem字节流转为AES密钥
// func pemToAES(raw []byte, pwd []byte) ([]byte, error) {
// 	if len(raw) == 0 {
// 		return nil, errors.New("invalid PEM. It must be different from nil")
// 	}
// 	block, _ := pem.Decode(raw)
// 	if block == nil {
// 		return nil, fmt.Errorf("failed decoding PEM. Block must be different from nil [% x]", raw)
// 	}

// 	if gmx509.IsEncryptedPEMBlock(block) {
// 		if len(pwd) == 0 {
// 			return nil, errors.New("encrypted Key. Password must be different fom nil")
// 		}

// 		decrypted, err := gmx509.DecryptPEMBlock(block, pwd)
// 		if err != nil {
// 			return nil, fmt.Errorf("failed PEM decryption: [%s]", err)
// 		}
// 		return decrypted, nil
// 	}

// 	return block.Bytes, nil
// }

// 将pem字节流转为sm4密钥
func pemToSM4(raw []byte, pwd []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("invalid PEM. It must be different from nil")
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("failed decoding PEM. Block must be different from nil. [% x]", raw)
	}

	if gmx509.IsEncryptedPEMBlock(block) {
		if len(pwd) == 0 {
			return nil, errors.New("encrypted Key. Password must be different fom nil")
		}
		decrypted, err := gmx509.DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, fmt.Errorf("failed PEM decryption. [%s]", err)
		}
		return decrypted, nil
	}

	return block.Bytes, nil
}

// // 将AES密钥转为pem字节流
// func aesToPEM(raw []byte) []byte {
// 	return pem.EncodeToMemory(&pem.Block{Type: "AES PRIVATE KEY", Bytes: raw})
// }

// 将sm4密钥转为pem字节流
func sm4ToPEM(raw []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "SM4 PRIVATE KEY", Bytes: raw})
}

// // 将AES密钥转为加密pem字节流
// func aesToEncryptedPEM(raw []byte, pwd []byte) ([]byte, error) {
// 	if len(raw) == 0 {
// 		return nil, errors.New("invalid aes key. It must be different from nil")
// 	}
// 	if len(pwd) == 0 {
// 		return aesToPEM(raw), nil
// 	}

// 	block, err := gmx509.EncryptPEMBlock(
// 		rand.Reader,
// 		"AES PRIVATE KEY",
// 		raw,
// 		pwd,
// 		gmx509.PEMCipherAES256)

// 	if err != nil {
// 		return nil, err
// 	}

// 	return pem.EncodeToMemory(block), nil
// }

// 将sm4密钥转为加密pem字节流
func sm4ToEncryptedPEM(raw []byte, pwd []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("invalid sm4 key. It must be different from nil")
	}
	if len(pwd) == 0 {
		return sm4ToPEM(raw), nil
	}

	block, err := gmx509.EncryptPEMBlock(
		rand.Reader,
		"ENCRYPTED SM4 PRIVATE KEY",
		raw,
		pwd,
		gmx509.PEMCipherSM4)

	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(block), nil
}

// publicKeyToPEM marshals a public key to the pem format. 将公钥转为pem字节流。
// 对于sm2公钥，转为PKIX格式字节流并包装为pem字节流
// 国密对应后只支持sm2
func publicKeyToPEM(publicKey interface{}, pwd []byte) ([]byte, error) {
	if len(pwd) != 0 {
		return publicKeyToEncryptedPEM(publicKey, pwd)
	}

	if publicKey == nil {
		return nil, errors.New("invalid public key. It must be different from nil")
	}

	switch k := publicKey.(type) {
	// case *ecdsa.PublicKey:
	// 	if k == nil {
	// 		return nil, errors.New("invalid ecdsa public key. It must be different from nil")
	// 	}
	// 	PubASN1, err := x509.MarshalPKIXPublicKey(k)
	// 	if err != nil {
	// 		return nil, err
	// 	}

	// 	return pem.EncodeToMemory(
	// 		&pem.Block{
	// 			Type:  "PUBLIC KEY",
	// 			Bytes: PubASN1,
	// 		},
	// 	), nil
	// case *rsa.PublicKey:
	// 	if k == nil {
	// 		return nil, errors.New("invalid rsa public key. It must be different from nil")
	// 	}
	// 	PubASN1, err := x509.MarshalPKIXPublicKey(k)
	// 	if err != nil {
	// 		return nil, err
	// 	}

	// 	return pem.EncodeToMemory(
	// 		&pem.Block{
	// 			Type:  "RSA PUBLIC KEY",
	// 			Bytes: PubASN1,
	// 		},
	// 	), nil
	case *sm2.PublicKey:
		if k == nil {
			return nil, errors.New("invalid sm2 public key. It must be different from nil")
		}
		return gmx509.WritePublicKeyToPem(k)
	default:
		return nil, errors.New("invalid key type. It must be *sm2.PublicKey")
	}
}

// publicKeyToDER marshals a public key to the der format. 将公钥转为der字节流
// 国密对应后只支持sm2
func publicKeyToDER(publicKey interface{}) ([]byte, error) {
	if publicKey == nil {
		return nil, errors.New("invalid public key. It must be different from nil")
	}

	switch k := publicKey.(type) {
	// case *ecdsa.PublicKey:
	// 	if k == nil {
	// 		return nil, errors.New("invalid ecdsa public key. It must be different from nil")
	// 	}
	// 	PubASN1, err := x509.MarshalPKIXPublicKey(k)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	return PubASN1, nil
	// case *rsa.PublicKey:
	// 	if k == nil {
	// 		return nil, errors.New("invalid rsa public key. It must be different from nil")
	// 	}
	// 	PubASN1, err := x509.MarshalPKIXPublicKey(k)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	return PubASN1, nil
	case *sm2.PublicKey:
		if k == nil {
			return nil, errors.New("invalid sm2 public key. It must be different from nil")
		}
		return gmx509.MarshalPKIXPublicKey(k)
	default:
		return nil, errors.New("invalid key type. It must be *sm2.PublicKey")
	}
}

// publicKeyToEncryptedPEM converts a public key to encrypted pem.将公钥转为加密pem字节流。
// 对于sm2公钥，转为PKIX格式字节流并包装为pem字节流
// 国密对应后只支持sm2
func publicKeyToEncryptedPEM(publicKey interface{}, pwd []byte) ([]byte, error) {
	if publicKey == nil {
		return nil, errors.New("invalid public key. It must be different from nil")
	}
	if len(pwd) == 0 {
		return nil, errors.New("invalid password. It must be different from nil")
	}
	switch k := publicKey.(type) {
	// case *ecdsa.PublicKey:
	// 	if k == nil {
	// 		return nil, errors.New("invalid ecdsa public key. It must be different from nil")
	// 	}
	// 	raw, err := x509.MarshalPKIXPublicKey(k)
	// 	if err != nil {
	// 		return nil, err
	// 	}

	// 	block, err := gmx509.EncryptPEMBlock(
	// 		rand.Reader,
	// 		"PUBLIC KEY",
	// 		raw,
	// 		pwd,
	// 		gmx509.PEMCipherAES256)

	// 	if err != nil {
	// 		return nil, err
	// 	}

	// 	return pem.EncodeToMemory(block), nil
	case *sm2.PublicKey:
		if k == nil {
			return nil, errors.New("invalid sm2 public key. It must be different from nil")
		}
		raw, err := gmx509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, err
		}
		block, err := gmx509.EncryptPEMBlock(
			rand.Reader,
			"ENCRYPTED SM2 PUBLIC KEY",
			raw,
			pwd,
			gmx509.PEMCipherSM4)

		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(block), nil
	default:
		return nil, errors.New("invalid key type. It must be *sm2.PublicKey")
	}
}

// 将pem字节流转为公钥
// 依次尝试 sm2, ecdsa, rsa
// 国密对应后只支持sm2
func pemToPublicKey(raw []byte, pwd []byte) (interface{}, error) {
	if len(raw) == 0 {
		return nil, errors.New("invalid PEM. It must be different from nil")
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("failed decoding. Block must be different from nil. [% x]", raw)
	}

	// derive from header the type of the key
	if gmx509.IsEncryptedPEMBlock(block) {
		if len(pwd) == 0 {
			return nil, errors.New("encrypted Key. Password must be different from nil")
		}
		decrypted, err := gmx509.DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, fmt.Errorf("failed PEM decryption: [%s]", err)
		}
		key, err := derToPublicKey(decrypted)
		if err != nil {
			return nil, err
		}
		return key, err
	}

	key, err := derToPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, err
}

// 将pem字节流转为sm2公钥
func pemToSm2PublicKey(raw []byte, pwd []byte) (*sm2.PublicKey, error) {
	pubKey, err := pemToPublicKey(raw, pwd)
	if err != nil {
		return nil, err
	}
	key, ok := pubKey.(*sm2.PublicKey)
	if !ok {
		return nil, errors.New("bccsp/sw/keys.go pemToSm2PublicKey : pem is not sm2 PublicKey")
	}
	return key, nil
}

// // 将pem字节流转为ecdsa或rsa公钥
// func pemToEcdsaPublicKey(raw []byte, pwd []byte) (interface{}, error) {
// 	if len(raw) == 0 {
// 		return nil, errors.New("invalid PEM. It must be different from nil")
// 	}
// 	block, _ := pem.Decode(raw)
// 	if block == nil {
// 		return nil, fmt.Errorf("failed decoding. Block must be different from nil [% x]", raw)
// 	}

// 	// derive from header the type of the key
// 	if gmx509.IsEncryptedPEMBlock(block) {
// 		if len(pwd) == 0 {
// 			return nil, errors.New("encrypted Key. Password must be different from nil")
// 		}

// 		decrypted, err := gmx509.DecryptPEMBlock(block, pwd)
// 		if err != nil {
// 			return nil, fmt.Errorf("failed PEM decryption: [%s]", err)
// 		}

// 		key, err := derToEcdsaPublicKey(decrypted)
// 		if err != nil {
// 			return nil, err
// 		}
// 		return key, err
// 	}

// 	cert, err := derToEcdsaPublicKey(block.Bytes)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return cert, err
// }

// 将der字节流转为公钥
// 依次尝试 sm2, ecdsa, rsa
// 国密对应后只支持sm2
func derToPublicKey(raw []byte) (pub interface{}, err error) {
	if len(raw) == 0 {
		return nil, errors.New("invalid DER. It must be different from nil")
	}
	pubkey, err := gmx509.ParsePKIXPublicKey(raw)
	return pubkey, err
}

// 将der字节流转为sm2公钥
func derToSm2PublicKey(raw []byte) (*sm2.PublicKey, error) {
	pubkey, err := derToPublicKey(raw)
	if err != nil {
		return nil, err
	}
	key, ok := pubkey.(*sm2.PublicKey)
	if !ok {
		return nil, errors.New("bccsp/sw/keys.go derToSm2PublicKey : der is not sm2 PublicKey")
	}
	return key, nil
}

// // 将der字节流转为ecdsa或rsa公钥
// func derToEcdsaPublicKey(raw []byte) (pub interface{}, err error) {
// 	if len(raw) == 0 {
// 		return nil, errors.New("invalid DER. It must be different from nil")
// 	}

// 	key, err := x509.ParsePKIXPublicKey(raw)
// 	return key, err
// }
