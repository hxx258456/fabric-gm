// Code generated by counterfeiter. DO NOT EDIT.
package mock

import (
	"context"
	"sync"

	"github.com/hxx258456/fabric-protos-go-gm/common"
	"github.com/hxx258456/fabric-protos-go-gm/orderer"
	"github.com/hxx258456/ccgo/grpc/metadata"
)

type ABServer struct {
	ContextStub        func() context.Context
	contextMutex       sync.RWMutex
	contextArgsForCall []struct {
	}
	contextReturns struct {
		result1 context.Context
	}
	contextReturnsOnCall map[int]struct {
		result1 context.Context
	}
	RecvStub        func() (*common.Envelope, error)
	recvMutex       sync.RWMutex
	recvArgsForCall []struct {
	}
	recvReturns struct {
		result1 *common.Envelope
		result2 error
	}
	recvReturnsOnCall map[int]struct {
		result1 *common.Envelope
		result2 error
	}
	RecvMsgStub        func(interface{}) error
	recvMsgMutex       sync.RWMutex
	recvMsgArgsForCall []struct {
		arg1 interface{}
	}
	recvMsgReturns struct {
		result1 error
	}
	recvMsgReturnsOnCall map[int]struct {
		result1 error
	}
	SendStub        func(*orderer.BroadcastResponse) error
	sendMutex       sync.RWMutex
	sendArgsForCall []struct {
		arg1 *orderer.BroadcastResponse
	}
	sendReturns struct {
		result1 error
	}
	sendReturnsOnCall map[int]struct {
		result1 error
	}
	SendHeaderStub        func(metadata.MD) error
	sendHeaderMutex       sync.RWMutex
	sendHeaderArgsForCall []struct {
		arg1 metadata.MD
	}
	sendHeaderReturns struct {
		result1 error
	}
	sendHeaderReturnsOnCall map[int]struct {
		result1 error
	}
	SendMsgStub        func(interface{}) error
	sendMsgMutex       sync.RWMutex
	sendMsgArgsForCall []struct {
		arg1 interface{}
	}
	sendMsgReturns struct {
		result1 error
	}
	sendMsgReturnsOnCall map[int]struct {
		result1 error
	}
	SetHeaderStub        func(metadata.MD) error
	setHeaderMutex       sync.RWMutex
	setHeaderArgsForCall []struct {
		arg1 metadata.MD
	}
	setHeaderReturns struct {
		result1 error
	}
	setHeaderReturnsOnCall map[int]struct {
		result1 error
	}
	SetTrailerStub        func(metadata.MD)
	setTrailerMutex       sync.RWMutex
	setTrailerArgsForCall []struct {
		arg1 metadata.MD
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *ABServer) Context() context.Context {
	fake.contextMutex.Lock()
	ret, specificReturn := fake.contextReturnsOnCall[len(fake.contextArgsForCall)]
	fake.contextArgsForCall = append(fake.contextArgsForCall, struct {
	}{})
	fake.recordInvocation("Context", []interface{}{})
	fake.contextMutex.Unlock()
	if fake.ContextStub != nil {
		return fake.ContextStub()
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.contextReturns
	return fakeReturns.result1
}

func (fake *ABServer) ContextCallCount() int {
	fake.contextMutex.RLock()
	defer fake.contextMutex.RUnlock()
	return len(fake.contextArgsForCall)
}

func (fake *ABServer) ContextCalls(stub func() context.Context) {
	fake.contextMutex.Lock()
	defer fake.contextMutex.Unlock()
	fake.ContextStub = stub
}

func (fake *ABServer) ContextReturns(result1 context.Context) {
	fake.contextMutex.Lock()
	defer fake.contextMutex.Unlock()
	fake.ContextStub = nil
	fake.contextReturns = struct {
		result1 context.Context
	}{result1}
}

func (fake *ABServer) ContextReturnsOnCall(i int, result1 context.Context) {
	fake.contextMutex.Lock()
	defer fake.contextMutex.Unlock()
	fake.ContextStub = nil
	if fake.contextReturnsOnCall == nil {
		fake.contextReturnsOnCall = make(map[int]struct {
			result1 context.Context
		})
	}
	fake.contextReturnsOnCall[i] = struct {
		result1 context.Context
	}{result1}
}

func (fake *ABServer) Recv() (*common.Envelope, error) {
	fake.recvMutex.Lock()
	ret, specificReturn := fake.recvReturnsOnCall[len(fake.recvArgsForCall)]
	fake.recvArgsForCall = append(fake.recvArgsForCall, struct {
	}{})
	fake.recordInvocation("Recv", []interface{}{})
	fake.recvMutex.Unlock()
	if fake.RecvStub != nil {
		return fake.RecvStub()
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.recvReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *ABServer) RecvCallCount() int {
	fake.recvMutex.RLock()
	defer fake.recvMutex.RUnlock()
	return len(fake.recvArgsForCall)
}

func (fake *ABServer) RecvCalls(stub func() (*common.Envelope, error)) {
	fake.recvMutex.Lock()
	defer fake.recvMutex.Unlock()
	fake.RecvStub = stub
}

func (fake *ABServer) RecvReturns(result1 *common.Envelope, result2 error) {
	fake.recvMutex.Lock()
	defer fake.recvMutex.Unlock()
	fake.RecvStub = nil
	fake.recvReturns = struct {
		result1 *common.Envelope
		result2 error
	}{result1, result2}
}

func (fake *ABServer) RecvReturnsOnCall(i int, result1 *common.Envelope, result2 error) {
	fake.recvMutex.Lock()
	defer fake.recvMutex.Unlock()
	fake.RecvStub = nil
	if fake.recvReturnsOnCall == nil {
		fake.recvReturnsOnCall = make(map[int]struct {
			result1 *common.Envelope
			result2 error
		})
	}
	fake.recvReturnsOnCall[i] = struct {
		result1 *common.Envelope
		result2 error
	}{result1, result2}
}

func (fake *ABServer) RecvMsg(arg1 interface{}) error {
	fake.recvMsgMutex.Lock()
	ret, specificReturn := fake.recvMsgReturnsOnCall[len(fake.recvMsgArgsForCall)]
	fake.recvMsgArgsForCall = append(fake.recvMsgArgsForCall, struct {
		arg1 interface{}
	}{arg1})
	fake.recordInvocation("RecvMsg", []interface{}{arg1})
	fake.recvMsgMutex.Unlock()
	if fake.RecvMsgStub != nil {
		return fake.RecvMsgStub(arg1)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.recvMsgReturns
	return fakeReturns.result1
}

func (fake *ABServer) RecvMsgCallCount() int {
	fake.recvMsgMutex.RLock()
	defer fake.recvMsgMutex.RUnlock()
	return len(fake.recvMsgArgsForCall)
}

func (fake *ABServer) RecvMsgCalls(stub func(interface{}) error) {
	fake.recvMsgMutex.Lock()
	defer fake.recvMsgMutex.Unlock()
	fake.RecvMsgStub = stub
}

func (fake *ABServer) RecvMsgArgsForCall(i int) interface{} {
	fake.recvMsgMutex.RLock()
	defer fake.recvMsgMutex.RUnlock()
	argsForCall := fake.recvMsgArgsForCall[i]
	return argsForCall.arg1
}

func (fake *ABServer) RecvMsgReturns(result1 error) {
	fake.recvMsgMutex.Lock()
	defer fake.recvMsgMutex.Unlock()
	fake.RecvMsgStub = nil
	fake.recvMsgReturns = struct {
		result1 error
	}{result1}
}

func (fake *ABServer) RecvMsgReturnsOnCall(i int, result1 error) {
	fake.recvMsgMutex.Lock()
	defer fake.recvMsgMutex.Unlock()
	fake.RecvMsgStub = nil
	if fake.recvMsgReturnsOnCall == nil {
		fake.recvMsgReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.recvMsgReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *ABServer) Send(arg1 *orderer.BroadcastResponse) error {
	fake.sendMutex.Lock()
	ret, specificReturn := fake.sendReturnsOnCall[len(fake.sendArgsForCall)]
	fake.sendArgsForCall = append(fake.sendArgsForCall, struct {
		arg1 *orderer.BroadcastResponse
	}{arg1})
	fake.recordInvocation("Send", []interface{}{arg1})
	fake.sendMutex.Unlock()
	if fake.SendStub != nil {
		return fake.SendStub(arg1)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.sendReturns
	return fakeReturns.result1
}

func (fake *ABServer) SendCallCount() int {
	fake.sendMutex.RLock()
	defer fake.sendMutex.RUnlock()
	return len(fake.sendArgsForCall)
}

func (fake *ABServer) SendCalls(stub func(*orderer.BroadcastResponse) error) {
	fake.sendMutex.Lock()
	defer fake.sendMutex.Unlock()
	fake.SendStub = stub
}

func (fake *ABServer) SendArgsForCall(i int) *orderer.BroadcastResponse {
	fake.sendMutex.RLock()
	defer fake.sendMutex.RUnlock()
	argsForCall := fake.sendArgsForCall[i]
	return argsForCall.arg1
}

func (fake *ABServer) SendReturns(result1 error) {
	fake.sendMutex.Lock()
	defer fake.sendMutex.Unlock()
	fake.SendStub = nil
	fake.sendReturns = struct {
		result1 error
	}{result1}
}

func (fake *ABServer) SendReturnsOnCall(i int, result1 error) {
	fake.sendMutex.Lock()
	defer fake.sendMutex.Unlock()
	fake.SendStub = nil
	if fake.sendReturnsOnCall == nil {
		fake.sendReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.sendReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *ABServer) SendHeader(arg1 metadata.MD) error {
	fake.sendHeaderMutex.Lock()
	ret, specificReturn := fake.sendHeaderReturnsOnCall[len(fake.sendHeaderArgsForCall)]
	fake.sendHeaderArgsForCall = append(fake.sendHeaderArgsForCall, struct {
		arg1 metadata.MD
	}{arg1})
	fake.recordInvocation("SendHeader", []interface{}{arg1})
	fake.sendHeaderMutex.Unlock()
	if fake.SendHeaderStub != nil {
		return fake.SendHeaderStub(arg1)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.sendHeaderReturns
	return fakeReturns.result1
}

func (fake *ABServer) SendHeaderCallCount() int {
	fake.sendHeaderMutex.RLock()
	defer fake.sendHeaderMutex.RUnlock()
	return len(fake.sendHeaderArgsForCall)
}

func (fake *ABServer) SendHeaderCalls(stub func(metadata.MD) error) {
	fake.sendHeaderMutex.Lock()
	defer fake.sendHeaderMutex.Unlock()
	fake.SendHeaderStub = stub
}

func (fake *ABServer) SendHeaderArgsForCall(i int) metadata.MD {
	fake.sendHeaderMutex.RLock()
	defer fake.sendHeaderMutex.RUnlock()
	argsForCall := fake.sendHeaderArgsForCall[i]
	return argsForCall.arg1
}

func (fake *ABServer) SendHeaderReturns(result1 error) {
	fake.sendHeaderMutex.Lock()
	defer fake.sendHeaderMutex.Unlock()
	fake.SendHeaderStub = nil
	fake.sendHeaderReturns = struct {
		result1 error
	}{result1}
}

func (fake *ABServer) SendHeaderReturnsOnCall(i int, result1 error) {
	fake.sendHeaderMutex.Lock()
	defer fake.sendHeaderMutex.Unlock()
	fake.SendHeaderStub = nil
	if fake.sendHeaderReturnsOnCall == nil {
		fake.sendHeaderReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.sendHeaderReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *ABServer) SendMsg(arg1 interface{}) error {
	fake.sendMsgMutex.Lock()
	ret, specificReturn := fake.sendMsgReturnsOnCall[len(fake.sendMsgArgsForCall)]
	fake.sendMsgArgsForCall = append(fake.sendMsgArgsForCall, struct {
		arg1 interface{}
	}{arg1})
	fake.recordInvocation("SendMsg", []interface{}{arg1})
	fake.sendMsgMutex.Unlock()
	if fake.SendMsgStub != nil {
		return fake.SendMsgStub(arg1)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.sendMsgReturns
	return fakeReturns.result1
}

func (fake *ABServer) SendMsgCallCount() int {
	fake.sendMsgMutex.RLock()
	defer fake.sendMsgMutex.RUnlock()
	return len(fake.sendMsgArgsForCall)
}

func (fake *ABServer) SendMsgCalls(stub func(interface{}) error) {
	fake.sendMsgMutex.Lock()
	defer fake.sendMsgMutex.Unlock()
	fake.SendMsgStub = stub
}

func (fake *ABServer) SendMsgArgsForCall(i int) interface{} {
	fake.sendMsgMutex.RLock()
	defer fake.sendMsgMutex.RUnlock()
	argsForCall := fake.sendMsgArgsForCall[i]
	return argsForCall.arg1
}

func (fake *ABServer) SendMsgReturns(result1 error) {
	fake.sendMsgMutex.Lock()
	defer fake.sendMsgMutex.Unlock()
	fake.SendMsgStub = nil
	fake.sendMsgReturns = struct {
		result1 error
	}{result1}
}

func (fake *ABServer) SendMsgReturnsOnCall(i int, result1 error) {
	fake.sendMsgMutex.Lock()
	defer fake.sendMsgMutex.Unlock()
	fake.SendMsgStub = nil
	if fake.sendMsgReturnsOnCall == nil {
		fake.sendMsgReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.sendMsgReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *ABServer) SetHeader(arg1 metadata.MD) error {
	fake.setHeaderMutex.Lock()
	ret, specificReturn := fake.setHeaderReturnsOnCall[len(fake.setHeaderArgsForCall)]
	fake.setHeaderArgsForCall = append(fake.setHeaderArgsForCall, struct {
		arg1 metadata.MD
	}{arg1})
	fake.recordInvocation("SetHeader", []interface{}{arg1})
	fake.setHeaderMutex.Unlock()
	if fake.SetHeaderStub != nil {
		return fake.SetHeaderStub(arg1)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.setHeaderReturns
	return fakeReturns.result1
}

func (fake *ABServer) SetHeaderCallCount() int {
	fake.setHeaderMutex.RLock()
	defer fake.setHeaderMutex.RUnlock()
	return len(fake.setHeaderArgsForCall)
}

func (fake *ABServer) SetHeaderCalls(stub func(metadata.MD) error) {
	fake.setHeaderMutex.Lock()
	defer fake.setHeaderMutex.Unlock()
	fake.SetHeaderStub = stub
}

func (fake *ABServer) SetHeaderArgsForCall(i int) metadata.MD {
	fake.setHeaderMutex.RLock()
	defer fake.setHeaderMutex.RUnlock()
	argsForCall := fake.setHeaderArgsForCall[i]
	return argsForCall.arg1
}

func (fake *ABServer) SetHeaderReturns(result1 error) {
	fake.setHeaderMutex.Lock()
	defer fake.setHeaderMutex.Unlock()
	fake.SetHeaderStub = nil
	fake.setHeaderReturns = struct {
		result1 error
	}{result1}
}

func (fake *ABServer) SetHeaderReturnsOnCall(i int, result1 error) {
	fake.setHeaderMutex.Lock()
	defer fake.setHeaderMutex.Unlock()
	fake.SetHeaderStub = nil
	if fake.setHeaderReturnsOnCall == nil {
		fake.setHeaderReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.setHeaderReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *ABServer) SetTrailer(arg1 metadata.MD) {
	fake.setTrailerMutex.Lock()
	fake.setTrailerArgsForCall = append(fake.setTrailerArgsForCall, struct {
		arg1 metadata.MD
	}{arg1})
	fake.recordInvocation("SetTrailer", []interface{}{arg1})
	fake.setTrailerMutex.Unlock()
	if fake.SetTrailerStub != nil {
		fake.SetTrailerStub(arg1)
	}
}

func (fake *ABServer) SetTrailerCallCount() int {
	fake.setTrailerMutex.RLock()
	defer fake.setTrailerMutex.RUnlock()
	return len(fake.setTrailerArgsForCall)
}

func (fake *ABServer) SetTrailerCalls(stub func(metadata.MD)) {
	fake.setTrailerMutex.Lock()
	defer fake.setTrailerMutex.Unlock()
	fake.SetTrailerStub = stub
}

func (fake *ABServer) SetTrailerArgsForCall(i int) metadata.MD {
	fake.setTrailerMutex.RLock()
	defer fake.setTrailerMutex.RUnlock()
	argsForCall := fake.setTrailerArgsForCall[i]
	return argsForCall.arg1
}

func (fake *ABServer) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.contextMutex.RLock()
	defer fake.contextMutex.RUnlock()
	fake.recvMutex.RLock()
	defer fake.recvMutex.RUnlock()
	fake.recvMsgMutex.RLock()
	defer fake.recvMsgMutex.RUnlock()
	fake.sendMutex.RLock()
	defer fake.sendMutex.RUnlock()
	fake.sendHeaderMutex.RLock()
	defer fake.sendHeaderMutex.RUnlock()
	fake.sendMsgMutex.RLock()
	defer fake.sendMsgMutex.RUnlock()
	fake.setHeaderMutex.RLock()
	defer fake.setHeaderMutex.RUnlock()
	fake.setTrailerMutex.RLock()
	defer fake.setTrailerMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *ABServer) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}
