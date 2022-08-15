/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"fmt"

	"gitee.com/zhaochuninhefei/fabric-chaincode-go-gm/shim"
	pb "gitee.com/zhaochuninhefei/fabric-protos-go-gm/peer"
)

// No-op test chaincode
type TestChaincode struct{}

func (t *TestChaincode) Init(stub shim.ChaincodeStubInterface) pb.Response {
	return shim.Success(nil)
}

func (t *TestChaincode) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	return shim.Success(nil)
}

func main() {
	err := shim.Start(new(TestChaincode))
	if err != nil {
		fmt.Printf("Error starting Simple chaincode: %s", err)
	}
}
