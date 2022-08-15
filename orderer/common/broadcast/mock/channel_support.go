// Code generated by counterfeiter. DO NOT EDIT.
package mock

import (
	"sync"

	"github.com/hxx258456/fabric-protos-go-gm/common"
	"github.com/hxx258456/fabric-gm/orderer/common/broadcast"
	"github.com/hxx258456/fabric-gm/orderer/common/msgprocessor"
)

type ChannelSupport struct {
	ClassifyMsgStub        func(*common.ChannelHeader) msgprocessor.Classification
	classifyMsgMutex       sync.RWMutex
	classifyMsgArgsForCall []struct {
		arg1 *common.ChannelHeader
	}
	classifyMsgReturns struct {
		result1 msgprocessor.Classification
	}
	classifyMsgReturnsOnCall map[int]struct {
		result1 msgprocessor.Classification
	}
	ConfigureStub        func(*common.Envelope, uint64) error
	configureMutex       sync.RWMutex
	configureArgsForCall []struct {
		arg1 *common.Envelope
		arg2 uint64
	}
	configureReturns struct {
		result1 error
	}
	configureReturnsOnCall map[int]struct {
		result1 error
	}
	OrderStub        func(*common.Envelope, uint64) error
	orderMutex       sync.RWMutex
	orderArgsForCall []struct {
		arg1 *common.Envelope
		arg2 uint64
	}
	orderReturns struct {
		result1 error
	}
	orderReturnsOnCall map[int]struct {
		result1 error
	}
	ProcessConfigMsgStub        func(*common.Envelope) (*common.Envelope, uint64, error)
	processConfigMsgMutex       sync.RWMutex
	processConfigMsgArgsForCall []struct {
		arg1 *common.Envelope
	}
	processConfigMsgReturns struct {
		result1 *common.Envelope
		result2 uint64
		result3 error
	}
	processConfigMsgReturnsOnCall map[int]struct {
		result1 *common.Envelope
		result2 uint64
		result3 error
	}
	ProcessConfigUpdateMsgStub        func(*common.Envelope) (*common.Envelope, uint64, error)
	processConfigUpdateMsgMutex       sync.RWMutex
	processConfigUpdateMsgArgsForCall []struct {
		arg1 *common.Envelope
	}
	processConfigUpdateMsgReturns struct {
		result1 *common.Envelope
		result2 uint64
		result3 error
	}
	processConfigUpdateMsgReturnsOnCall map[int]struct {
		result1 *common.Envelope
		result2 uint64
		result3 error
	}
	ProcessNormalMsgStub        func(*common.Envelope) (uint64, error)
	processNormalMsgMutex       sync.RWMutex
	processNormalMsgArgsForCall []struct {
		arg1 *common.Envelope
	}
	processNormalMsgReturns struct {
		result1 uint64
		result2 error
	}
	processNormalMsgReturnsOnCall map[int]struct {
		result1 uint64
		result2 error
	}
	WaitReadyStub        func() error
	waitReadyMutex       sync.RWMutex
	waitReadyArgsForCall []struct {
	}
	waitReadyReturns struct {
		result1 error
	}
	waitReadyReturnsOnCall map[int]struct {
		result1 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *ChannelSupport) ClassifyMsg(arg1 *common.ChannelHeader) msgprocessor.Classification {
	fake.classifyMsgMutex.Lock()
	ret, specificReturn := fake.classifyMsgReturnsOnCall[len(fake.classifyMsgArgsForCall)]
	fake.classifyMsgArgsForCall = append(fake.classifyMsgArgsForCall, struct {
		arg1 *common.ChannelHeader
	}{arg1})
	fake.recordInvocation("ClassifyMsg", []interface{}{arg1})
	fake.classifyMsgMutex.Unlock()
	if fake.ClassifyMsgStub != nil {
		return fake.ClassifyMsgStub(arg1)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.classifyMsgReturns
	return fakeReturns.result1
}

func (fake *ChannelSupport) ClassifyMsgCallCount() int {
	fake.classifyMsgMutex.RLock()
	defer fake.classifyMsgMutex.RUnlock()
	return len(fake.classifyMsgArgsForCall)
}

func (fake *ChannelSupport) ClassifyMsgCalls(stub func(*common.ChannelHeader) msgprocessor.Classification) {
	fake.classifyMsgMutex.Lock()
	defer fake.classifyMsgMutex.Unlock()
	fake.ClassifyMsgStub = stub
}

func (fake *ChannelSupport) ClassifyMsgArgsForCall(i int) *common.ChannelHeader {
	fake.classifyMsgMutex.RLock()
	defer fake.classifyMsgMutex.RUnlock()
	argsForCall := fake.classifyMsgArgsForCall[i]
	return argsForCall.arg1
}

func (fake *ChannelSupport) ClassifyMsgReturns(result1 msgprocessor.Classification) {
	fake.classifyMsgMutex.Lock()
	defer fake.classifyMsgMutex.Unlock()
	fake.ClassifyMsgStub = nil
	fake.classifyMsgReturns = struct {
		result1 msgprocessor.Classification
	}{result1}
}

func (fake *ChannelSupport) ClassifyMsgReturnsOnCall(i int, result1 msgprocessor.Classification) {
	fake.classifyMsgMutex.Lock()
	defer fake.classifyMsgMutex.Unlock()
	fake.ClassifyMsgStub = nil
	if fake.classifyMsgReturnsOnCall == nil {
		fake.classifyMsgReturnsOnCall = make(map[int]struct {
			result1 msgprocessor.Classification
		})
	}
	fake.classifyMsgReturnsOnCall[i] = struct {
		result1 msgprocessor.Classification
	}{result1}
}

func (fake *ChannelSupport) Configure(arg1 *common.Envelope, arg2 uint64) error {
	fake.configureMutex.Lock()
	ret, specificReturn := fake.configureReturnsOnCall[len(fake.configureArgsForCall)]
	fake.configureArgsForCall = append(fake.configureArgsForCall, struct {
		arg1 *common.Envelope
		arg2 uint64
	}{arg1, arg2})
	fake.recordInvocation("Configure", []interface{}{arg1, arg2})
	fake.configureMutex.Unlock()
	if fake.ConfigureStub != nil {
		return fake.ConfigureStub(arg1, arg2)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.configureReturns
	return fakeReturns.result1
}

func (fake *ChannelSupport) ConfigureCallCount() int {
	fake.configureMutex.RLock()
	defer fake.configureMutex.RUnlock()
	return len(fake.configureArgsForCall)
}

func (fake *ChannelSupport) ConfigureCalls(stub func(*common.Envelope, uint64) error) {
	fake.configureMutex.Lock()
	defer fake.configureMutex.Unlock()
	fake.ConfigureStub = stub
}

func (fake *ChannelSupport) ConfigureArgsForCall(i int) (*common.Envelope, uint64) {
	fake.configureMutex.RLock()
	defer fake.configureMutex.RUnlock()
	argsForCall := fake.configureArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2
}

func (fake *ChannelSupport) ConfigureReturns(result1 error) {
	fake.configureMutex.Lock()
	defer fake.configureMutex.Unlock()
	fake.ConfigureStub = nil
	fake.configureReturns = struct {
		result1 error
	}{result1}
}

func (fake *ChannelSupport) ConfigureReturnsOnCall(i int, result1 error) {
	fake.configureMutex.Lock()
	defer fake.configureMutex.Unlock()
	fake.ConfigureStub = nil
	if fake.configureReturnsOnCall == nil {
		fake.configureReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.configureReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *ChannelSupport) Order(arg1 *common.Envelope, arg2 uint64) error {
	fake.orderMutex.Lock()
	ret, specificReturn := fake.orderReturnsOnCall[len(fake.orderArgsForCall)]
	fake.orderArgsForCall = append(fake.orderArgsForCall, struct {
		arg1 *common.Envelope
		arg2 uint64
	}{arg1, arg2})
	fake.recordInvocation("Order", []interface{}{arg1, arg2})
	fake.orderMutex.Unlock()
	if fake.OrderStub != nil {
		return fake.OrderStub(arg1, arg2)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.orderReturns
	return fakeReturns.result1
}

func (fake *ChannelSupport) OrderCallCount() int {
	fake.orderMutex.RLock()
	defer fake.orderMutex.RUnlock()
	return len(fake.orderArgsForCall)
}

func (fake *ChannelSupport) OrderCalls(stub func(*common.Envelope, uint64) error) {
	fake.orderMutex.Lock()
	defer fake.orderMutex.Unlock()
	fake.OrderStub = stub
}

func (fake *ChannelSupport) OrderArgsForCall(i int) (*common.Envelope, uint64) {
	fake.orderMutex.RLock()
	defer fake.orderMutex.RUnlock()
	argsForCall := fake.orderArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2
}

func (fake *ChannelSupport) OrderReturns(result1 error) {
	fake.orderMutex.Lock()
	defer fake.orderMutex.Unlock()
	fake.OrderStub = nil
	fake.orderReturns = struct {
		result1 error
	}{result1}
}

func (fake *ChannelSupport) OrderReturnsOnCall(i int, result1 error) {
	fake.orderMutex.Lock()
	defer fake.orderMutex.Unlock()
	fake.OrderStub = nil
	if fake.orderReturnsOnCall == nil {
		fake.orderReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.orderReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *ChannelSupport) ProcessConfigMsg(arg1 *common.Envelope) (*common.Envelope, uint64, error) {
	fake.processConfigMsgMutex.Lock()
	ret, specificReturn := fake.processConfigMsgReturnsOnCall[len(fake.processConfigMsgArgsForCall)]
	fake.processConfigMsgArgsForCall = append(fake.processConfigMsgArgsForCall, struct {
		arg1 *common.Envelope
	}{arg1})
	fake.recordInvocation("ProcessConfigMsg", []interface{}{arg1})
	fake.processConfigMsgMutex.Unlock()
	if fake.ProcessConfigMsgStub != nil {
		return fake.ProcessConfigMsgStub(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2, ret.result3
	}
	fakeReturns := fake.processConfigMsgReturns
	return fakeReturns.result1, fakeReturns.result2, fakeReturns.result3
}

func (fake *ChannelSupport) ProcessConfigMsgCallCount() int {
	fake.processConfigMsgMutex.RLock()
	defer fake.processConfigMsgMutex.RUnlock()
	return len(fake.processConfigMsgArgsForCall)
}

func (fake *ChannelSupport) ProcessConfigMsgCalls(stub func(*common.Envelope) (*common.Envelope, uint64, error)) {
	fake.processConfigMsgMutex.Lock()
	defer fake.processConfigMsgMutex.Unlock()
	fake.ProcessConfigMsgStub = stub
}

func (fake *ChannelSupport) ProcessConfigMsgArgsForCall(i int) *common.Envelope {
	fake.processConfigMsgMutex.RLock()
	defer fake.processConfigMsgMutex.RUnlock()
	argsForCall := fake.processConfigMsgArgsForCall[i]
	return argsForCall.arg1
}

func (fake *ChannelSupport) ProcessConfigMsgReturns(result1 *common.Envelope, result2 uint64, result3 error) {
	fake.processConfigMsgMutex.Lock()
	defer fake.processConfigMsgMutex.Unlock()
	fake.ProcessConfigMsgStub = nil
	fake.processConfigMsgReturns = struct {
		result1 *common.Envelope
		result2 uint64
		result3 error
	}{result1, result2, result3}
}

func (fake *ChannelSupport) ProcessConfigMsgReturnsOnCall(i int, result1 *common.Envelope, result2 uint64, result3 error) {
	fake.processConfigMsgMutex.Lock()
	defer fake.processConfigMsgMutex.Unlock()
	fake.ProcessConfigMsgStub = nil
	if fake.processConfigMsgReturnsOnCall == nil {
		fake.processConfigMsgReturnsOnCall = make(map[int]struct {
			result1 *common.Envelope
			result2 uint64
			result3 error
		})
	}
	fake.processConfigMsgReturnsOnCall[i] = struct {
		result1 *common.Envelope
		result2 uint64
		result3 error
	}{result1, result2, result3}
}

func (fake *ChannelSupport) ProcessConfigUpdateMsg(arg1 *common.Envelope) (*common.Envelope, uint64, error) {
	fake.processConfigUpdateMsgMutex.Lock()
	ret, specificReturn := fake.processConfigUpdateMsgReturnsOnCall[len(fake.processConfigUpdateMsgArgsForCall)]
	fake.processConfigUpdateMsgArgsForCall = append(fake.processConfigUpdateMsgArgsForCall, struct {
		arg1 *common.Envelope
	}{arg1})
	fake.recordInvocation("ProcessConfigUpdateMsg", []interface{}{arg1})
	fake.processConfigUpdateMsgMutex.Unlock()
	if fake.ProcessConfigUpdateMsgStub != nil {
		return fake.ProcessConfigUpdateMsgStub(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2, ret.result3
	}
	fakeReturns := fake.processConfigUpdateMsgReturns
	return fakeReturns.result1, fakeReturns.result2, fakeReturns.result3
}

func (fake *ChannelSupport) ProcessConfigUpdateMsgCallCount() int {
	fake.processConfigUpdateMsgMutex.RLock()
	defer fake.processConfigUpdateMsgMutex.RUnlock()
	return len(fake.processConfigUpdateMsgArgsForCall)
}

func (fake *ChannelSupport) ProcessConfigUpdateMsgCalls(stub func(*common.Envelope) (*common.Envelope, uint64, error)) {
	fake.processConfigUpdateMsgMutex.Lock()
	defer fake.processConfigUpdateMsgMutex.Unlock()
	fake.ProcessConfigUpdateMsgStub = stub
}

func (fake *ChannelSupport) ProcessConfigUpdateMsgArgsForCall(i int) *common.Envelope {
	fake.processConfigUpdateMsgMutex.RLock()
	defer fake.processConfigUpdateMsgMutex.RUnlock()
	argsForCall := fake.processConfigUpdateMsgArgsForCall[i]
	return argsForCall.arg1
}

func (fake *ChannelSupport) ProcessConfigUpdateMsgReturns(result1 *common.Envelope, result2 uint64, result3 error) {
	fake.processConfigUpdateMsgMutex.Lock()
	defer fake.processConfigUpdateMsgMutex.Unlock()
	fake.ProcessConfigUpdateMsgStub = nil
	fake.processConfigUpdateMsgReturns = struct {
		result1 *common.Envelope
		result2 uint64
		result3 error
	}{result1, result2, result3}
}

func (fake *ChannelSupport) ProcessConfigUpdateMsgReturnsOnCall(i int, result1 *common.Envelope, result2 uint64, result3 error) {
	fake.processConfigUpdateMsgMutex.Lock()
	defer fake.processConfigUpdateMsgMutex.Unlock()
	fake.ProcessConfigUpdateMsgStub = nil
	if fake.processConfigUpdateMsgReturnsOnCall == nil {
		fake.processConfigUpdateMsgReturnsOnCall = make(map[int]struct {
			result1 *common.Envelope
			result2 uint64
			result3 error
		})
	}
	fake.processConfigUpdateMsgReturnsOnCall[i] = struct {
		result1 *common.Envelope
		result2 uint64
		result3 error
	}{result1, result2, result3}
}

func (fake *ChannelSupport) ProcessNormalMsg(arg1 *common.Envelope) (uint64, error) {
	fake.processNormalMsgMutex.Lock()
	ret, specificReturn := fake.processNormalMsgReturnsOnCall[len(fake.processNormalMsgArgsForCall)]
	fake.processNormalMsgArgsForCall = append(fake.processNormalMsgArgsForCall, struct {
		arg1 *common.Envelope
	}{arg1})
	fake.recordInvocation("ProcessNormalMsg", []interface{}{arg1})
	fake.processNormalMsgMutex.Unlock()
	if fake.ProcessNormalMsgStub != nil {
		return fake.ProcessNormalMsgStub(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.processNormalMsgReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *ChannelSupport) ProcessNormalMsgCallCount() int {
	fake.processNormalMsgMutex.RLock()
	defer fake.processNormalMsgMutex.RUnlock()
	return len(fake.processNormalMsgArgsForCall)
}

func (fake *ChannelSupport) ProcessNormalMsgCalls(stub func(*common.Envelope) (uint64, error)) {
	fake.processNormalMsgMutex.Lock()
	defer fake.processNormalMsgMutex.Unlock()
	fake.ProcessNormalMsgStub = stub
}

func (fake *ChannelSupport) ProcessNormalMsgArgsForCall(i int) *common.Envelope {
	fake.processNormalMsgMutex.RLock()
	defer fake.processNormalMsgMutex.RUnlock()
	argsForCall := fake.processNormalMsgArgsForCall[i]
	return argsForCall.arg1
}

func (fake *ChannelSupport) ProcessNormalMsgReturns(result1 uint64, result2 error) {
	fake.processNormalMsgMutex.Lock()
	defer fake.processNormalMsgMutex.Unlock()
	fake.ProcessNormalMsgStub = nil
	fake.processNormalMsgReturns = struct {
		result1 uint64
		result2 error
	}{result1, result2}
}

func (fake *ChannelSupport) ProcessNormalMsgReturnsOnCall(i int, result1 uint64, result2 error) {
	fake.processNormalMsgMutex.Lock()
	defer fake.processNormalMsgMutex.Unlock()
	fake.ProcessNormalMsgStub = nil
	if fake.processNormalMsgReturnsOnCall == nil {
		fake.processNormalMsgReturnsOnCall = make(map[int]struct {
			result1 uint64
			result2 error
		})
	}
	fake.processNormalMsgReturnsOnCall[i] = struct {
		result1 uint64
		result2 error
	}{result1, result2}
}

func (fake *ChannelSupport) WaitReady() error {
	fake.waitReadyMutex.Lock()
	ret, specificReturn := fake.waitReadyReturnsOnCall[len(fake.waitReadyArgsForCall)]
	fake.waitReadyArgsForCall = append(fake.waitReadyArgsForCall, struct {
	}{})
	fake.recordInvocation("WaitReady", []interface{}{})
	fake.waitReadyMutex.Unlock()
	if fake.WaitReadyStub != nil {
		return fake.WaitReadyStub()
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.waitReadyReturns
	return fakeReturns.result1
}

func (fake *ChannelSupport) WaitReadyCallCount() int {
	fake.waitReadyMutex.RLock()
	defer fake.waitReadyMutex.RUnlock()
	return len(fake.waitReadyArgsForCall)
}

func (fake *ChannelSupport) WaitReadyCalls(stub func() error) {
	fake.waitReadyMutex.Lock()
	defer fake.waitReadyMutex.Unlock()
	fake.WaitReadyStub = stub
}

func (fake *ChannelSupport) WaitReadyReturns(result1 error) {
	fake.waitReadyMutex.Lock()
	defer fake.waitReadyMutex.Unlock()
	fake.WaitReadyStub = nil
	fake.waitReadyReturns = struct {
		result1 error
	}{result1}
}

func (fake *ChannelSupport) WaitReadyReturnsOnCall(i int, result1 error) {
	fake.waitReadyMutex.Lock()
	defer fake.waitReadyMutex.Unlock()
	fake.WaitReadyStub = nil
	if fake.waitReadyReturnsOnCall == nil {
		fake.waitReadyReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.waitReadyReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *ChannelSupport) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.classifyMsgMutex.RLock()
	defer fake.classifyMsgMutex.RUnlock()
	fake.configureMutex.RLock()
	defer fake.configureMutex.RUnlock()
	fake.orderMutex.RLock()
	defer fake.orderMutex.RUnlock()
	fake.processConfigMsgMutex.RLock()
	defer fake.processConfigMsgMutex.RUnlock()
	fake.processConfigUpdateMsgMutex.RLock()
	defer fake.processConfigUpdateMsgMutex.RUnlock()
	fake.processNormalMsgMutex.RLock()
	defer fake.processNormalMsgMutex.RUnlock()
	fake.waitReadyMutex.RLock()
	defer fake.waitReadyMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *ChannelSupport) recordInvocation(key string, args []interface{}) {
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

var _ broadcast.ChannelSupport = new(ChannelSupport)
