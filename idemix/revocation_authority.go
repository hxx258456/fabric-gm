/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package idemix

import (
	//	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"math/big"

	"github.com/hxx258456/ccgo/sm2"
	"github.com/hxx258456/ccgo/sm3"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-amcl/amcl"
	"github.com/hyperledger/fabric-amcl/amcl/FP256BN"
	"github.com/pkg/errors"
)

type RevocationAlgorithm int32

const (
	ALG_NO_REVOCATION RevocationAlgorithm = iota
)

var ProofBytes = map[RevocationAlgorithm]int{
	ALG_NO_REVOCATION: 0,
}

// GenerateLongTermRevocationKey generates a long term signing key that will be used for revocation
func GenerateLongTermRevocationKey() (*sm2.PrivateKey, error) {
	// TODO: 为什么用于撤销的长期签名私钥使用ecdsa？而User和IssUer都是fabric自己的一种密钥?
	//	return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	return sm2.GenerateKey(rand.Reader)
}

// CreateCRI creates the Credential Revocation Information for a certain time period (epoch).
// Users can use the CRI to prove that they are not revoked.
// Note that when not using revocation (i.e., alg = ALG_NO_REVOCATION), the entered unrevokedHandles are not used,
// and the resulting CRI can be used by any signer.
func CreateCRI(key *sm2.PrivateKey, unrevokedHandles []*FP256BN.BIG, epoch int, alg RevocationAlgorithm, rng *amcl.RAND) (*CredentialRevocationInformation, error) {
	if key == nil || rng == nil {
		return nil, errors.Errorf("CreateCRI received nil input")
	}
	cri := &CredentialRevocationInformation{}
	cri.RevocationAlg = int32(alg)
	cri.Epoch = int64(epoch)

	if alg == ALG_NO_REVOCATION {
		// put a dummy PK in the proto
		cri.EpochPk = Ecp2ToProto(GenG2)
	} else {
		// create epoch key
		_, epochPk := WBBKeyGen(rng)
		cri.EpochPk = Ecp2ToProto(epochPk)
	}

	// sign epoch + epoch key with long term key
	bytesToSign, err := proto.Marshal(cri)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal CRI")
	}
	// 改为sm3
	digest := sm3.Sm3Sum(bytesToSign)

	cri.EpochPkSig, err = key.Sign(rand.Reader, digest[:], nil)
	if err != nil {
		return nil, err
	}

	if alg == ALG_NO_REVOCATION {
		return cri, nil
	} else {
		return nil, errors.Errorf("the specified revocation algorithm is not supported.")
	}
}

// VerifyEpochPK verifies that the revocation PK for a certain epoch is valid,
// by checking that it was signed with the long term revocation key.
// Note that even if we use no revocation (i.e., alg = ALG_NO_REVOCATION), we need
// to verify the signature to make sure the issuer indeed signed that no revocation
// is used in this epoch.
func VerifyEpochPK(pk *sm2.PublicKey, epochPK *ECP2, epochPkSig []byte, epoch int, alg RevocationAlgorithm) error {
	if pk == nil || epochPK == nil {
		return errors.Errorf("EpochPK invalid: received nil input")
	}
	cri := &CredentialRevocationInformation{}
	cri.RevocationAlg = int32(alg)
	cri.EpochPk = epochPK
	cri.Epoch = int64(epoch)
	bytesToSign, err := proto.Marshal(cri)
	if err != nil {
		return err
	}
	// 改为sm3
	digest := sm3.Sm3Sum(bytesToSign)

	var sig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(epochPkSig, &sig); err != nil {
		return errors.Wrap(err, "failed unmashalling signature")
	}

	// TODO Verify -> Sm2Verify
	if !sm2.Sm2Verify(pk, digest[:], nil, sig.R, sig.S) {
		return errors.Errorf("EpochPKSig invalid")
	}

	return nil
}
