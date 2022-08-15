package test

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hxx258456/ccgo/sm4"
	gmx509 "github.com/hxx258456/ccgo/x509"
	"github.com/hxx258456/fabric-gm/bccsp"
	"github.com/hxx258456/fabric-gm/bccsp/factory"
	"github.com/hxx258456/fabric-gm/bccsp/sw"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestUsingGM(t *testing.T) {
	// bccsp工厂配置(yaml)
	yamlCFG := `
BCCSP:
    default: SW
    SW:
        Hash: SM3
        Security: 256
    UsingGM: "y"
`
	csp, err := readYaml2Bccsp(yamlCFG)
	if err != nil {
		t.Fatalf("读取YAML到BCCSP失败: %s", err)
	}
	fmt.Printf("csp 支持的算法: %s\n", (*csp).ShowAlgorithms())

	// 定义明文
	plaintext := []byte("月黑见渔灯，孤光一点萤。微微风簇浪，散作满河星。")
	fmt.Printf("明文: %s\n", plaintext)

	// 对称加密

	// 获取sm4密钥
	sm4Key, err := (*csp).KeyGen(&bccsp.SM4KeyGenOpts{Temporary: true})
	if err != nil {
		t.Fatalf("生成sm4Key失败: %s", err)
	}
	sm4KeyBytes, err := sm4Key.Bytes()
	if err != nil {
		t.Fatalf("获取sm4KeyBytes失败: %s", err)
	}
	fmt.Printf("sm4密钥: %s\n", hex.EncodeToString(sm4KeyBytes))
	fmt.Printf("sm4密钥长度: %d\n", len(sm4KeyBytes))
	// 获取IV
	sm4IV, err := sw.GetRandomBytes(sm4.BlockSize)
	if err != nil {
		t.Fatalf("获取sm4IV失败: %s", err)
	}
	fmt.Printf("sm4IV: %s\n", hex.EncodeToString(sm4IV))

	// sm4加密
	sm4Opts := &bccsp.SM4EncrypterDecrypterOpts{
		// MODE: "OFB",
		IV: sm4IV}
	ciphertext, err := (*csp).Encrypt(sm4Key, plaintext, sm4Opts)
	if err != nil {
		t.Fatalf("sm4加密失败: %s", err)
	}
	fmt.Printf("密文: %s\n", hex.EncodeToString(ciphertext))
	// sm4解密
	textAfterDecrypt, err := (*csp).Decrypt(sm4Key, ciphertext, sm4Opts)
	if err != nil {
		t.Fatalf("sm4解密失败: %s", err)
	}
	fmt.Printf("解密后的明文: %s\n", textAfterDecrypt)
	assert.Equal(t, plaintext, textAfterDecrypt)

	// 散列
	digest1, err := (*csp).Hash(plaintext, &bccsp.SM3Opts{})
	if err != nil {
		t.Fatalf("sm3散列失败: %s", err)
	}
	fmt.Printf("sm3散列: %s\n", hex.EncodeToString(digest1))
	digest2, err := (*csp).Hash(textAfterDecrypt, &bccsp.SM3Opts{})
	if err != nil {
		t.Fatalf("sm3散列失败: %s", err)
	}
	fmt.Printf("sm3散列: %s\n", hex.EncodeToString(digest2))
	assert.Equal(t, digest1, digest2)

	// 生成sm2密钥对
	sm2Priv, err := (*csp).KeyGen(&bccsp.SM2KeyGenOpts{Temporary: true})
	if err != nil {
		t.Fatalf("生成sm2密钥对失败: %s", err)
	}
	sm2Pub, _ := sm2Priv.PublicKey()
	sm2PrivBytes, _ := sm2Priv.Bytes()
	sm2PubBytes, _ := sm2Pub.Bytes()
	fmt.Printf("sm2私钥: %s\n", hex.EncodeToString(sm2PrivBytes))
	fmt.Printf("sm2公钥: %s\n", hex.EncodeToString(sm2PubBytes))

	// sm2私钥签名
	sign, err := (*csp).Sign(sm2Priv, digest1, nil)
	if err != nil {
		t.Fatalf("sm2签名失败: %s", err)
	}
	fmt.Printf("sm2签名: %s\n", hex.EncodeToString(sign))
	// sm2公钥验签
	valid, err := (*csp).Verify(sm2Pub, sign, digest1, nil)
	if err != nil {
		t.Fatalf("sm2公钥验签失败: %s", err)
	}
	if valid {
		fmt.Println("sm2公钥验签成功")
	}
	assert.Equal(t, true, valid)
	// sm2私钥验签
	valid2, err := (*csp).Verify(sm2Priv, sign, digest1, nil)
	if err != nil {
		t.Fatalf("sm2私钥验签失败: %s", err)
	}
	if valid2 {
		fmt.Println("sm2私钥验签成功")
	}
	assert.Equal(t, true, valid2)
}

// func TestNotUsingGM(t *testing.T) {
// 	// bccsp工厂配置(yaml)
// 	yamlCFG := `
// BCCSP:
//     default: SW
//     SW:
//         Hash: SHA3
//         Security: 384
//     UsingGM: "n"
// `
// 	csp, err := readYaml2Bccsp(yamlCFG)
// 	if err != nil {
// 		t.Fatalf("读取YAML到BCCSP失败: %s", err)
// 	}
// 	fmt.Printf("csp 支持的算法: %s\n", (*csp).ShowAlgorithms())

// 	// 定义明文
// 	plaintext := []byte("月黑见渔灯，孤光一点萤。微微风簇浪，散作满河星。")
// 	fmt.Printf("明文: %s\n", plaintext)

// 	// 对称加密

// 	// 获取aes密钥
// 	aesKey, err := (*csp).KeyGen(&bccsp.AESKeyGenOpts{Temporary: true})
// 	if err != nil {
// 		t.Fatalf("生成aesKey失败: %s", err)
// 	}
// 	aesKeyBytes, err := aesKey.Bytes()
// 	if err != nil {
// 		t.Fatalf("获取aesKeyBytes失败: %s", err)
// 	}
// 	fmt.Printf("aes密钥: %s\n", hex.EncodeToString(aesKeyBytes))
// 	fmt.Printf("aes密钥长度: %d\n", len(aesKeyBytes))
// 	// 获取IV
// 	aesIV, err := sw.GetRandomBytes(aes.BlockSize)
// 	if err != nil {
// 		t.Fatalf("获取aesIV失败: %s", err)
// 	}
// 	fmt.Printf("aesIV: %s\n", hex.EncodeToString(aesIV))

// 	// aes加密
// 	aesOpts := &bccsp.AESCBCPKCS7ModeOpts{
// 		IV: aesIV,
// 		// PRNG: rand.Reader,
// 	}
// 	ciphertext, err := (*csp).Encrypt(aesKey, plaintext, aesOpts)
// 	if err != nil {
// 		t.Fatalf("aes加密失败: %s", err)
// 	}
// 	fmt.Printf("密文: %s\n", hex.EncodeToString(ciphertext))
// 	// aes解密
// 	textAfterDecrypt, err := (*csp).Decrypt(aesKey, ciphertext, aesOpts)
// 	if err != nil {
// 		t.Fatalf("aes解密失败: %s", err)
// 	}
// 	fmt.Printf("解密后的明文: %s\n", textAfterDecrypt)
// 	assert.Equal(t, plaintext, textAfterDecrypt)

// 	// 散列
// 	digest1, err := (*csp).Hash(plaintext, &bccsp.SHAOpts{})
// 	if err != nil {
// 		t.Fatalf("sha散列失败: %s", err)
// 	}
// 	fmt.Printf("sha散列: %s\n", hex.EncodeToString(digest1))
// 	digest2, err := (*csp).Hash(textAfterDecrypt, &bccsp.SHAOpts{})
// 	if err != nil {
// 		t.Fatalf("sha散列失败: %s", err)
// 	}
// 	fmt.Printf("sha散列: %s\n", hex.EncodeToString(digest2))
// 	assert.Equal(t, digest1, digest2)

// 	// 生成ecdsa密钥对
// 	ecdsaPriv, err := (*csp).KeyGen(&bccsp.ECDSAKeyGenOpts{Temporary: true})
// 	if err != nil {
// 		t.Fatalf("生成sm2密钥对失败: %s", err)
// 	}
// 	ecdsaPub, _ := ecdsaPriv.PublicKey()
// 	ecdsaPrivBytes, _ := ecdsaPriv.Bytes()
// 	ecdsaPubBytes, _ := ecdsaPub.Bytes()
// 	fmt.Printf("ecdsa私钥: %s\n", hex.EncodeToString(ecdsaPrivBytes))
// 	fmt.Printf("ecdsa公钥: %s\n", hex.EncodeToString(ecdsaPubBytes))

// 	// ecdsa私钥签名
// 	sign, err := (*csp).Sign(ecdsaPriv, digest1, nil)
// 	if err != nil {
// 		t.Fatalf("ecdsa签名失败: %s", err)
// 	}
// 	fmt.Printf("ecdsa签名: %s\n", hex.EncodeToString(sign))
// 	// ecdsa公钥验签
// 	valid, err := (*csp).Verify(ecdsaPub, sign, digest1, nil)
// 	if err != nil {
// 		t.Fatalf("ecdsa公钥验签失败: %s", err)
// 	}
// 	if valid {
// 		fmt.Println("ecdsa公钥验签成功")
// 	}
// 	assert.Equal(t, true, valid)
// 	// ecdsa私钥验签
// 	valid2, err := (*csp).Verify(ecdsaPriv, sign, digest1, nil)
// 	if err != nil {
// 		t.Fatalf("ecdsa私钥验签失败: %s", err)
// 	}
// 	if valid2 {
// 		fmt.Println("ecdsa私钥验签成功")
// 	}
// 	assert.Equal(t, true, valid2)
// }

func TestCreateCertFromCA(t *testing.T) {
	// bccsp工厂配置(yaml)
	yamlCFG := `
BCCSP:
    default: SW
    SW:
        Hash: SM3
        Security: 256
    UsingGM: "y"
`
	csp, err := readYaml2Bccsp(yamlCFG)
	if err != nil {
		t.Fatalf("读取YAML到BCCSP失败: %s", err)
	}
	fmt.Printf("csp 支持的算法: %s\n", (*csp).ShowAlgorithms())

	caPriv, caCert, err := createCACert(csp)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("生成CA密钥对与CA证书成功")

	err = createSignCert(csp, caPriv, caCert)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("生成sm2_sign密钥对并模拟CA为其颁发证书成功")
}

// 创建ca证书，并返回ca私钥与ca证书
func createCACert(csp *bccsp.BCCSP) (*bccsp.Key, *gmx509.Certificate, error) {
	certType := "sm2_ca"
	// 生成 certSm2 密钥对
	sm2Priv, err := (*csp).KeyGen(&bccsp.SM2KeyGenOpts{Temporary: true})
	if err != nil {
		return nil, nil, err
	}
	sm2Pub, _ := sm2Priv.PublicKey()
	sm2PrivBytes, _ := sm2Priv.Bytes()
	sm2PubBytes, _ := sm2Pub.Bytes()
	fmt.Printf("certSm2私钥: %s\n", hex.EncodeToString(sm2PrivBytes))
	fmt.Printf("certSm2公钥: %s\n", hex.EncodeToString(sm2PubBytes))

	userKeyUsage := gmx509.KeyUsageCertSign + gmx509.KeyUsageCRLSign
	userExtKeyUsage := []gmx509.ExtKeyUsage{
		// ExtKeyUsageAny,
		// ExtKeyUsageServerAuth,
		// ExtKeyUsageClientAuth,
		// ExtKeyUsageCodeSigning,
		// ExtKeyUsageEmailProtection,
		// ExtKeyUsageIPSECEndSystem,
		// ExtKeyUsageIPSECTunnel,
		// ExtKeyUsageIPSECUser,
		// ExtKeyUsageTimeStamping,
		// ExtKeyUsageOCSPSigning,
		// ExtKeyUsageMicrosoftServerGatedCrypto,
		// ExtKeyUsageNetscapeServerGatedCrypto,
	}
	// // 使用公钥生成ski
	// sid := CreateEllipticSKI(pubKey.Curve, pubKey.X, pubKey.Y)
	// aid := sid
	// 创建证书，ca证书自签名
	cert, err := createCertSignSelf("ca.test.com", "catest", "CN", "Anhui Hefei", true, true, userKeyUsage, userExtKeyUsage, nil, certType, &sm2Pub, &sm2Priv)
	if err != nil {
		return nil, nil, err
	}
	// 检查证书签名，因为是ca证书自签名，所以使用本证书自验
	err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		return nil, nil, err
	} else {
		fmt.Printf("CheckSignature ok\n")
	}
	return &sm2Priv, cert, nil
}

func createSignCert(csp *bccsp.BCCSP, caPriv *bccsp.Key, caCert *gmx509.Certificate) error {
	certType := "sm2_sign"
	// 生成 sm2 密钥对
	sm2Priv, err := (*csp).KeyGen(&bccsp.SM2KeyGenOpts{Temporary: true})
	if err != nil {
		return err
	}
	sm2Pub, _ := sm2Priv.PublicKey()
	sm2PrivBytes, _ := sm2Priv.Bytes()
	sm2PubBytes, _ := sm2Pub.Bytes()
	fmt.Printf("certSm2私钥: %s\n", hex.EncodeToString(sm2PrivBytes))
	fmt.Printf("certSm2公钥: %s\n", hex.EncodeToString(sm2PubBytes))

	userKeyUsage := gmx509.KeyUsageDigitalSignature + gmx509.KeyUsageContentCommitment
	userExtKeyUsage := []gmx509.ExtKeyUsage{
		// ExtKeyUsageAny,
		gmx509.ExtKeyUsageServerAuth,
		gmx509.ExtKeyUsageClientAuth,
		// ExtKeyUsageCodeSigning,
		// ExtKeyUsageEmailProtection,
		// ExtKeyUsageIPSECEndSystem,
		// ExtKeyUsageIPSECTunnel,
		// ExtKeyUsageIPSECUser,
		// ExtKeyUsageTimeStamping,
		// ExtKeyUsageOCSPSigning,
		// ExtKeyUsageMicrosoftServerGatedCrypto,
		// ExtKeyUsageNetscapeServerGatedCrypto,
	}
	// sid := []byte{0, 0, 0, 2}
	// aid := caCert.SubjectKeyId
	// 模拟CA颁发证书，注意此时ca证书是父证书
	cert, err := createCertSignParent("server.test.com", "server_test", "CN", "Anhui Hefei", false, false, userKeyUsage, userExtKeyUsage, nil, certType, &sm2Pub, caPriv, caCert)
	if err != nil {
		return err
	}
	// 使用父证书caCert验签
	err = caCert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		return err
	} else {
		fmt.Printf("CheckSignature ok\n")
	}
	return nil
}

func createCertSignSelf(cn string, o string, c string, st string, bcs bool, isca bool,
	ku gmx509.KeyUsage, ekus []gmx509.ExtKeyUsage, uekus []asn1.ObjectIdentifier,
	certType string, pubKey, privKey *bccsp.Key) (*gmx509.Certificate, error) {
	pubK := (*pubKey).InsideKey()
	privK := (*privKey).InsideKey()
	// 获取ski
	ski := (*pubKey).SKI()
	// 定义证书模板
	template := createTemplate(cn, o, c, st, bcs, isca, ski, ku, ekus, uekus)
	// 创建自签名证书pem文件
	_, err := gmx509.CreateCertificateToPemFile("testdata/"+certType+"_cert.cer", template, template, pubK, privK)
	if err != nil {
		return nil, err
	}
	// 可以使用命令`openssl x509 -noout -text -in testdata/user_cert.cer`查看生成的x509证书
	// 读取证书pem文件
	cert, err := gmx509.ReadCertificateFromPemFile("testdata/" + certType + "_cert.cer")
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func createCertSignParent(cn string, o string, c string, st string, bcs bool, isca bool,
	ku gmx509.KeyUsage, ekus []gmx509.ExtKeyUsage, uekus []asn1.ObjectIdentifier,
	certType string, pubKey, privKey *bccsp.Key, parent *gmx509.Certificate) (*gmx509.Certificate, error) {
	pubK := (*pubKey).InsideKey()
	privK := (*privKey).InsideKey()
	// 获取ski
	ski := (*pubKey).SKI()
	// 定义证书模板
	template := createTemplate(cn, o, c, st, bcs, isca, ski, ku, ekus, uekus)
	// 创建自签名证书pem文件
	_, err := gmx509.CreateCertificateToPemFile("testdata/"+certType+"_cert.cer", template, parent, pubK, privK)
	if err != nil {
		return nil, err
	}
	// 可以使用命令`openssl x509 -noout -text -in testdata/user_cert.cer`查看生成的x509证书
	// 读取证书pem文件
	cert, err := gmx509.ReadCertificateFromPemFile("testdata/" + certType + "_cert.cer")
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func createTemplate(cn string, o string, c string, st string, bcs bool, isca bool, sId []byte,
	ku gmx509.KeyUsage, ekus []gmx509.ExtKeyUsage, uekus []asn1.ObjectIdentifier) *gmx509.Certificate {
	// 定义证书模板
	template := &gmx509.Certificate{
		// 证书序列号
		SerialNumber: sw.GetRandBigInt(),
		// 证书拥有者
		Subject: pkix.Name{
			// CN 证书拥有者通用名, 一般是域名
			CommonName: cn,
			// O 证书拥有者组织机构
			Organization: []string{o},
			// C 证书拥有者所在国家
			Country: []string{"China"},
			// 附加名称
			ExtraNames: []pkix.AttributeTypeAndValue{
				// This should override the Country, above.
				{
					// C 会覆盖Country
					Type:  []int{2, 5, 4, 6},
					Value: c,
				},
				{
					// ST 省市
					Type:  []int{2, 5, 4, 8},
					Value: st,
				},
			},
		},
		// 证书有效期 十年
		// NotBefore:             time.Now(),
		// NotAfter:              time.Date(2032, time.December, 31, 23, 59, 59, 1, time.UTC),
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(87600 * time.Hour),
		// 证书签名算法
		SignatureAlgorithm:    gmx509.SM2WithSM3,
		BasicConstraintsValid: bcs,
		IsCA:                  isca,
		SubjectKeyId:          sId,
		// AuthorityKeyId:        aId,
		KeyUsage:           ku,
		ExtKeyUsage:        ekus,
		UnknownExtKeyUsage: uekus,
	}
	return template
}

func readYaml2Bccsp(yamlCFG string) (*bccsp.BCCSP, error) {
	viper.SetConfigType("yaml")
	err := viper.ReadConfig(strings.NewReader(yamlCFG))
	if err != nil {
		return nil, err
	}
	var bccspFactoryOpts *factory.FactoryOpts
	err = viper.UnmarshalKey("bccsp", &bccspFactoryOpts)
	if err != nil {
		return nil, err
	}
	csp, err := factory.GetBCCSPFromOpts(bccspFactoryOpts)
	if err != nil {
		return nil, err
	}
	// fmt.Printf("csp 支持的算法: %s\n", csp.ShowAlgorithms())
	return &csp, nil
}
