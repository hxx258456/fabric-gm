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
	"math/big"

	"github.com/hxx258456/ccgo/sm2"
	gx509 "github.com/hxx258456/ccgo/x509"
	"github.com/hxx258456/fabric-gm/bccsp"
)

/*
 * bccsp/sw/certhelper.go 提供了gmx509证书相关函数
 */

// //调用SM2接口生成SM2证书
// func CreateCertificateToMem(template, parent *x509.Certificate,key bccsp.Key) (cert []byte,err error) {
// 	pk := key.(*sm2PrivateKey).privKey
// 	bigint := getRandBigInt()
// 	if(template.SerialNumber == nil){
// 		template.SerialNumber = bigint
// 	}
// 	if parent.SerialNumber == nil{
// 		parent.SerialNumber = bigint
// 	}

// 	sm2Temcert := ParseX509Certificate2Sm2(template)
// 	sm2Parcert := ParseX509Certificate2Sm2(parent)
// 	switch template.PublicKey.(type){
// 	case sm2.PublicKey:
// 		cert, err = sm2.CreateCertificateToMem(sm2Temcert,sm2Parcert, template.PublicKey.(*sm2.PublicKey),pk)
// 		return
// 	default:
// 		return nil ,fmt.Errorf("gm certhelper not sm2.PublicKey")
// 	}
// }

// //调用SM2接口生成SM2证书请求
// func CreateCertificateRequestToMem(certificateRequest *x509.CertificateRequest,key bccsp.Key) (csr []byte,err error) {
// 	pk := key.(*sm2PrivateKey).privKey
// 	sm2Req := ParseX509CertificateRequest2Sm2(certificateRequest)
// 	csr,err = sm2.CreateCertificateRequestToMem(sm2Req,pk)
// 	return
// }

// 根据证书模板生成证书pem字节流(sm2证书)
// template : 证书模板
// parent : 父证书
// key : 签名私钥
func CreateCertificateToMem(template, parent *gx509.Certificate, key bccsp.Key) (cert []byte, err error) {
	// 将参数 key 强转为sm2PrivateKey类型
	pk := key.(*SM2PrivateKey).privKey
	// 获取证书模板的公钥并强转为sm2.PublicKey
	pub, a := template.PublicKey.(*sm2.PublicKey)
	if a {
		// 复制一个sm2.PublicKey
		var puk sm2.PublicKey
		// 强制使用sm2的椭圆曲线
		puk.Curve = sm2.P256Sm2()
		// 复制公钥座标
		puk.X = pub.X
		puk.Y = pub.Y
		// 根据证书模板生成证书pem字节流，公钥为证书模板提供的公钥的复制，签名私钥为传入参数key强转后的sm2私钥
		cert, err = gx509.CreateCertificateToPem(template, parent, &puk, pk)

	}
	return
}

// 根据证书申请模板生成证书申请pem字节流，由申请者自签名
// certificateRequest : 证书申请模板(*gx509.CertificateRequest)
// key : 申请者私钥(*sm2PrivateKey)
func CreateSm2CertificateRequestToMem(certificateRequest *gx509.CertificateRequest, key bccsp.Key) (csr []byte, err error) {
	pk := key.(*SM2PrivateKey).privKey
	// 根据证书申请模板生成证书申请pem字节流，由申请者自签名
	csr, err = gx509.CreateCertificateRequestToPem(certificateRequest, pk)
	return
}

// // X509 证书请求转换为 gmx509证书请求
// func ParseX509CertificateRequest2Sm2(x509req *x509.CertificateRequest) *gx509.CertificateRequest {
// 	sm2req := &gx509.CertificateRequest{
// 		Raw:                      x509req.Raw,                      // Complete ASN.1 DER content (CSR, signature algorithm and signature).
// 		RawTBSCertificateRequest: x509req.RawTBSCertificateRequest, // Certificate request info part of raw ASN.1 DER content.
// 		RawSubjectPublicKeyInfo:  x509req.RawSubjectPublicKeyInfo,  // DER encoded SubjectPublicKeyInfo.
// 		RawSubject:               x509req.RawSubject,               // DER encoded Subject.

// 		Version:            x509req.Version,
// 		Signature:          x509req.Signature,
// 		SignatureAlgorithm: gx509.SignatureAlgorithm(x509req.SignatureAlgorithm),

// 		PublicKeyAlgorithm: gx509.PublicKeyAlgorithm(x509req.PublicKeyAlgorithm),
// 		PublicKey:          x509req.PublicKey,

// 		Subject: x509req.Subject,

// 		// Attributes is the dried husk of a bug and shouldn't be used.
// 		// Attributes: x509req.Attributes,

// 		// Extensions contains raw X.509 extensions. When parsing CSRs, this
// 		// can be used to extract extensions that are not parsed by this
// 		// package.
// 		Extensions: x509req.Extensions,

// 		// ExtraExtensions contains extensions to be copied, raw, into any
// 		// marshaled CSR. Values override any extensions that would otherwise
// 		// be produced based on the other fields but are overridden by any
// 		// extensions specified in Attributes.
// 		//
// 		// The ExtraExtensions field is not populated when parsing CSRs, see
// 		// Extensions.
// 		ExtraExtensions: x509req.ExtraExtensions,

// 		// Subject Alternate Name values.
// 		DNSNames:       x509req.DNSNames,
// 		EmailAddresses: x509req.EmailAddresses,
// 		IPAddresses:    x509req.IPAddresses,
// 	}
// 	return sm2req
// }

// X509证书转换为 gmx509证书
// func ParseX509Certificate2Sm2(x509Cert *x509.Certificate) *gx509.Certificate {
// 	sm2cert := &gx509.Certificate{
// 		Raw:                     x509Cert.Raw,
// 		RawTBSCertificate:       x509Cert.RawTBSCertificate,
// 		RawSubjectPublicKeyInfo: x509Cert.RawSubjectPublicKeyInfo,
// 		RawSubject:              x509Cert.RawSubject,
// 		RawIssuer:               x509Cert.RawIssuer,

// 		Signature:          x509Cert.Signature,
// 		SignatureAlgorithm: gx509.SignatureAlgorithm(x509Cert.SignatureAlgorithm),

// 		PublicKeyAlgorithm: gx509.PublicKeyAlgorithm(x509Cert.PublicKeyAlgorithm),
// 		PublicKey:          x509Cert.PublicKey,

// 		Version:      x509Cert.Version,
// 		SerialNumber: x509Cert.SerialNumber,
// 		Issuer:       x509Cert.Issuer,
// 		Subject:      x509Cert.Subject,
// 		NotBefore:    x509Cert.NotBefore,
// 		NotAfter:     x509Cert.NotAfter,
// 		KeyUsage:     gx509.KeyUsage(x509Cert.KeyUsage),

// 		Extensions: x509Cert.Extensions,

// 		ExtraExtensions: x509Cert.ExtraExtensions,

// 		UnhandledCriticalExtensions: x509Cert.UnhandledCriticalExtensions,

// 		//ExtKeyUsage:	[]x509.ExtKeyUsage(x509Cert.ExtKeyUsage) ,
// 		UnknownExtKeyUsage: x509Cert.UnknownExtKeyUsage,

// 		BasicConstraintsValid: x509Cert.BasicConstraintsValid,
// 		IsCA:                  x509Cert.IsCA,
// 		MaxPathLen:            x509Cert.MaxPathLen,
// 		// MaxPathLenZero indicates that BasicConstraintsValid==true and
// 		// MaxPathLen==0 should be interpreted as an actual maximum path length
// 		// of zero. Otherwise, that combination is interpreted as MaxPathLen
// 		// not being set.
// 		MaxPathLenZero: x509Cert.MaxPathLenZero,

// 		SubjectKeyId:   x509Cert.SubjectKeyId,
// 		AuthorityKeyId: x509Cert.AuthorityKeyId,

// 		// RFC 5280, 4.2.2.1 (Authority Information Access)
// 		OCSPServer:            x509Cert.OCSPServer,
// 		IssuingCertificateURL: x509Cert.IssuingCertificateURL,

// 		// Subject Alternate Name values
// 		DNSNames:       x509Cert.DNSNames,
// 		EmailAddresses: x509Cert.EmailAddresses,
// 		IPAddresses:    x509Cert.IPAddresses,

// 		// Name constraints
// 		PermittedDNSDomainsCritical: x509Cert.PermittedDNSDomainsCritical,
// 		PermittedDNSDomains:         x509Cert.PermittedDNSDomains,

// 		// CRL Distribution Points
// 		CRLDistributionPoints: x509Cert.CRLDistributionPoints,

// 		PolicyIdentifiers: x509Cert.PolicyIdentifiers,
// 	}
// 	for _, val := range x509Cert.ExtKeyUsage {
// 		sm2cert.ExtKeyUsage = append(sm2cert.ExtKeyUsage, gx509.ExtKeyUsage(val))
// 	}

// 	return sm2cert
// }

// // gmx509 证书转换为 x509 证书
// func ParseSm2Certificate2X509(gmx509Cert *gx509.Certificate) *x509.Certificate {
// 	if gmx509Cert == nil {
// 		return nil
// 	}
// 	x509cert := &x509.Certificate{
// 		Raw:                     gmx509Cert.Raw,
// 		RawTBSCertificate:       gmx509Cert.RawTBSCertificate,
// 		RawSubjectPublicKeyInfo: gmx509Cert.RawSubjectPublicKeyInfo,
// 		RawSubject:              gmx509Cert.RawSubject,
// 		RawIssuer:               gmx509Cert.RawIssuer,

// 		Signature:          gmx509Cert.Signature,
// 		SignatureAlgorithm: x509.SignatureAlgorithm(gmx509Cert.SignatureAlgorithm),

// 		PublicKeyAlgorithm: x509.PublicKeyAlgorithm(gmx509Cert.PublicKeyAlgorithm),
// 		PublicKey:          gmx509Cert.PublicKey,

// 		Version:      gmx509Cert.Version,
// 		SerialNumber: gmx509Cert.SerialNumber,
// 		Issuer:       gmx509Cert.Issuer,
// 		Subject:      gmx509Cert.Subject,
// 		NotBefore:    gmx509Cert.NotBefore,
// 		NotAfter:     gmx509Cert.NotAfter,
// 		KeyUsage:     x509.KeyUsage(gmx509Cert.KeyUsage),

// 		Extensions: gmx509Cert.Extensions,

// 		ExtraExtensions: gmx509Cert.ExtraExtensions,

// 		UnhandledCriticalExtensions: gmx509Cert.UnhandledCriticalExtensions,

// 		//ExtKeyUsage:	[]x509.ExtKeyUsage(sm2Cert.ExtKeyUsage) ,
// 		UnknownExtKeyUsage: gmx509Cert.UnknownExtKeyUsage,

// 		BasicConstraintsValid: gmx509Cert.BasicConstraintsValid,
// 		IsCA:                  gmx509Cert.IsCA,
// 		MaxPathLen:            gmx509Cert.MaxPathLen,
// 		// MaxPathLenZero indicates that BasicConstraintsValid==true and
// 		// MaxPathLen==0 should be interpreted as an actual maximum path length
// 		// of zero. Otherwise, that combination is interpreted as MaxPathLen
// 		// not being set.
// 		MaxPathLenZero: gmx509Cert.MaxPathLenZero,

// 		SubjectKeyId:   gmx509Cert.SubjectKeyId,
// 		AuthorityKeyId: gmx509Cert.AuthorityKeyId,

// 		// RFC 5280, 4.2.2.1 (Authority Information Access)
// 		OCSPServer:            gmx509Cert.OCSPServer,
// 		IssuingCertificateURL: gmx509Cert.IssuingCertificateURL,

// 		// Subject Alternate Name values
// 		DNSNames:       gmx509Cert.DNSNames,
// 		EmailAddresses: gmx509Cert.EmailAddresses,
// 		IPAddresses:    gmx509Cert.IPAddresses,

// 		// Name constraints
// 		PermittedDNSDomainsCritical: gmx509Cert.PermittedDNSDomainsCritical,
// 		PermittedDNSDomains:         gmx509Cert.PermittedDNSDomains,

// 		// CRL Distribution Points
// 		CRLDistributionPoints: gmx509Cert.CRLDistributionPoints,

// 		PolicyIdentifiers: gmx509Cert.PolicyIdentifiers,
// 	}
// 	for _, val := range gmx509Cert.ExtKeyUsage {
// 		x509cert.ExtKeyUsage = append(x509cert.ExtKeyUsage, x509.ExtKeyUsage(val))
// 	}

// 	return x509cert
// }

// 随机生成序列号
func GetRandBigInt() *big.Int {
	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}
	return sn
	// serialNumber := make([]byte, 20)
	// _, err := io.ReadFull(rand.Reader, serialNumber)
	// if err != nil {
	// 	// return nil, cferr.Wrap(cferr.CertificateError, cferr.Unknown, err)
	// }
	// // SetBytes interprets buf as the bytes of a big-endian
	// // unsigned integer. The leading byte should be masked
	// // off to ensure it isn't negative.
	// serialNumber[0] &= 0x7F
	// //template.SerialNumber = new(big.Int).SetBytes(serialNumber)
	// return new(big.Int).SetBytes(serialNumber)
}
