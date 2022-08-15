// Code generated by mockery v1.0.0. DO NOT EDIT.

package mocks

import mock "github.com/stretchr/testify/mock"

import validation "github.com/hxx258456/fabric-gm/core/handlers/validation/api/state"

// StateFetcher is an autogenerated mock type for the StateFetcher type
type StateFetcher struct {
	mock.Mock
}

// FetchState provides a mock function with given fields:
func (_m *StateFetcher) FetchState() (validation.State, error) {
	ret := _m.Called()

	var r0 validation.State
	if rf, ok := ret.Get(0).(func() validation.State); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(validation.State)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
