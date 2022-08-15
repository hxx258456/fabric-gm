/*
Copyright IBM Corp. 2017 All Rights Reserved.

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
	"errors"
	"reflect"
	"testing"

	"github.com/hxx258456/fabric-gm/bccsp"
	mocks2 "github.com/hxx258456/fabric-gm/bccsp/mocks"
	"github.com/hxx258456/fabric-gm/bccsp/sw/mocks"
	"github.com/stretchr/testify/assert"
)

func TestKeyDeriv(t *testing.T) {
	t.Parallel()

	expectedKey := &mocks2.MockKey{BytesValue: []byte{1, 2, 3}}
	expectedOpts := &mocks2.KeyDerivOpts{EphemeralValue: true}
	expectetValue := &mocks2.MockKey{BytesValue: []byte{1, 2, 3, 4, 5}}
	expectedErr := errors.New("Expected Error")

	keyDerivers := make(map[reflect.Type]KeyDeriver)
	keyDerivers[reflect.TypeOf(&mocks2.MockKey{})] = &mocks.KeyDeriver{
		KeyArg:  expectedKey,
		OptsArg: expectedOpts,
		Value:   expectetValue,
		Err:     expectedErr,
	}
	csp := CSP{KeyDerivers: keyDerivers}
	value, err := csp.KeyDeriv(expectedKey, expectedOpts)
	assert.Nil(t, value)
	assert.Contains(t, err.Error(), expectedErr.Error())

	keyDerivers = make(map[reflect.Type]KeyDeriver)
	keyDerivers[reflect.TypeOf(&mocks2.MockKey{})] = &mocks.KeyDeriver{
		KeyArg:  expectedKey,
		OptsArg: expectedOpts,
		Value:   expectetValue,
		Err:     nil,
	}
	csp = CSP{KeyDerivers: keyDerivers}
	value, err = csp.KeyDeriv(expectedKey, expectedOpts)
	assert.Equal(t, expectetValue, value)
	assert.Nil(t, err)
}

// func TestECDSAPublicKeyKeyDeriver(t *testing.T) {
// 	t.Parallel()

// 	kd := ecdsaPublicKeyKeyDeriver{}

// 	_, err := kd.KeyDeriv(&mocks2.MockKey{}, nil)
// 	assert.Error(t, err)
// 	assert.Contains(t, err.Error(), "invalid opts parameter. It must not be nil")

// 	_, err = kd.KeyDeriv(&ECDSAPublicKey{}, &mocks2.KeyDerivOpts{})
// 	assert.Error(t, err)
// 	assert.Contains(t, err.Error(), "unsupported 'KeyDerivOpts' provided [")
// }

// func TestECDSAPrivateKeyKeyDeriver(t *testing.T) {
// 	t.Parallel()

// 	kd := ecdsaPrivateKeyKeyDeriver{}

// 	_, err := kd.KeyDeriv(&mocks2.MockKey{}, nil)
// 	assert.Error(t, err)
// 	assert.Contains(t, err.Error(), "invalid opts parameter. It must not be nil")

// 	_, err = kd.KeyDeriv(&ECDSAPrivateKey{}, &mocks2.KeyDerivOpts{})
// 	assert.Error(t, err)
// 	assert.Contains(t, err.Error(), "unsupported 'KeyDerivOpts' provided [")
// }

// func TestAESPrivateKeyKeyDeriver(t *testing.T) {
// 	t.Parallel()

// 	kd := aesPrivateKeyKeyDeriver{}

// 	_, err := kd.KeyDeriv(&mocks2.MockKey{}, nil)
// 	assert.Error(t, err)
// 	assert.Contains(t, err.Error(), "invalid opts parameter. It must not be nil")

// 	_, err = kd.KeyDeriv(&AESPrivateKey{}, &mocks2.KeyDerivOpts{})
// 	assert.Error(t, err)
// 	assert.Contains(t, err.Error(), "unsupported 'KeyDerivOpts' provided [")
// }

func Test_smPublicKeyKeyDeriver_KeyDeriv(t *testing.T) {
	type args struct {
		key  bccsp.Key
		opts bccsp.KeyDerivOpts
	}
	tests := []struct {
		name    string
		kd      *smPublicKeyKeyDeriver
		args    args
		want    bccsp.Key
		wantErr bool
	}{
		// Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kd := &smPublicKeyKeyDeriver{}
			got, err := kd.KeyDeriv(tt.args.key, tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("smPublicKeyKeyDeriver.KeyDeriv() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("smPublicKeyKeyDeriver.KeyDeriv() = %v, want %v", got, tt.want)
			}
		})
	}
}
