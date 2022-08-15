/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dispatcher_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	lc "gitee.com/zhaochuninhefei/fabric-protos-go-gm/peer/lifecycle"
	"github.com/hxx258456/fabric-gm/core/dispatcher"

	"github.com/golang/protobuf/proto"
)

var _ = Describe("ProtobufImpl", func() {
	var (
		pi        *dispatcher.ProtobufImpl
		sampleMsg *lc.InstallChaincodeArgs
	)

	BeforeEach(func() {
		pi = &dispatcher.ProtobufImpl{}
		sampleMsg = &lc.InstallChaincodeArgs{
			ChaincodeInstallPackage: []byte("install-package"),
		}
	})

	Describe("Marshal", func() {
		It("passes through to the proto implementation", func() {
			res, err := pi.Marshal(sampleMsg)
			Expect(err).NotTo(HaveOccurred())

			msg := &lc.InstallChaincodeArgs{}
			err = proto.Unmarshal(res, msg)
			Expect(err).NotTo(HaveOccurred())
			Expect(proto.Equal(msg, sampleMsg)).To(BeTrue())
		})
	})

	Describe("Unmarshal", func() {
		It("passes through to the proto implementation", func() {
			res, err := proto.Marshal(sampleMsg)
			Expect(err).NotTo(HaveOccurred())

			msg := &lc.InstallChaincodeArgs{}
			err = pi.Unmarshal(res, msg)
			Expect(err).NotTo(HaveOccurred())
			Expect(proto.Equal(msg, sampleMsg)).To(BeTrue())
		})
	})
})
