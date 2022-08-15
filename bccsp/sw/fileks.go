/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/hxx258456/ccgo/sm2"
	"github.com/hxx258456/fabric-gm/bccsp"
)

/*
bccsp/sw/fileks.go 实现`bccsp.KeyStore`接口(bccsp/keystore.go)，用于key的文件存储读写功能
*/

// NewFileBasedKeyStore instantiated a file-based key store at a given position.
// The key store can be encrypted if a non-empty password is specified.
// It can be also be set as read only. In this case, any store operation
// will be forbidden
func NewFileBasedKeyStore(pwd []byte, path string, readOnly bool) (bccsp.KeyStore, error) {
	ks := &fileBasedKeyStore{}
	return ks, ks.Init(pwd, path, readOnly)
}

// fileBasedKeyStore is a folder-based KeyStore.
// Each key is stored in a separated file whose name contains the key's SKI
// and flags to identity the key's type. All the keys are stored in
// a folder whose path is provided at initialization time.
// The KeyStore can be initialized with a password, this password
// is used to encrypt and decrypt the files storing the keys.
// A KeyStore can be read only to avoid the overwriting of keys.
type fileBasedKeyStore struct {
	path string

	readOnly bool
	isOpen   bool

	pwd []byte

	// Sync
	m sync.Mutex
}

// Init initializes this KeyStore with a password, a path to a folder
// where the keys are stored and a read only flag.
// Each key is stored in a separated file whose name contains the key's SKI
// and flags to identity the key's type.
// If the KeyStore is initialized with a password, this password
// is used to encrypt and decrypt the files storing the keys.
// The pwd can be nil for non-encrypted KeyStores. If an encrypted
// key-store is initialized without a password, then retrieving keys from the
// KeyStore will fail.
// A KeyStore can be read only to avoid the overwriting of keys.
func (ks *fileBasedKeyStore) Init(pwd []byte, path string, readOnly bool) error {
	// Validate inputs
	// pwd can be nil

	if len(path) == 0 {
		return errors.New("an invalid KeyStore path provided. Path cannot be an empty string")
	}

	ks.m.Lock()
	defer ks.m.Unlock()

	if ks.isOpen {
		return errors.New("keystore is already initialized")
	}

	ks.path = path

	clone := make([]byte, len(pwd))
	copy(ks.pwd, pwd)
	ks.pwd = clone
	ks.readOnly = readOnly

	exists, err := dirExists(path)
	if err != nil {
		return err
	}
	if !exists {
		err = ks.createKeyStore()
		if err != nil {
			return err
		}
		return ks.openKeyStore()
	}

	empty, err := dirEmpty(path)
	if err != nil {
		return err
	}
	if empty {
		err = ks.createKeyStore()
		if err != nil {
			return err
		}
	}

	return ks.openKeyStore()
}

// ReadOnly returns true if this KeyStore is read only, false otherwise.
// If ReadOnly is true then StoreKey will fail.
func (ks *fileBasedKeyStore) ReadOnly() bool {
	return ks.readOnly
}

// GetKey returns a key object whose SKI is the one passed.
// 根据ski读取密钥或公私钥，ski作为别名alias使用
func (ks *fileBasedKeyStore) GetKey(ski []byte) (bccsp.Key, error) {
	// Validate arguments
	if len(ski) == 0 {
		return nil, errors.New("invalid SKI. Cannot be of zero length")
	}
	alias := hex.EncodeToString(ski)
	// 根据ski的16进制字符串获取后缀
	suffix := ks.getSuffix(alias)

	switch suffix {
	case "key":
		// Load the key
		key, err := ks.loadKey(suffix, alias)
		if err != nil {
			return nil, fmt.Errorf("failed loading key [%x] [%s]", ski, err)
		}

		return &SM4Key{key, false}, nil
	case "sk":
		// Load the private key
		key, err := ks.loadPrivateKey(suffix, alias)
		if err != nil {
			return nil, fmt.Errorf("failed loading secret key [%x] [%s]", ski, err)
		}

		switch k := key.(type) {
		// case *ecdsa.PrivateKey:
		// 	return &ECDSAPrivateKey{k}, nil
		case *sm2.PrivateKey:
			return &SM2PrivateKey{k}, nil
		default:
			return nil, errors.New("secret key type not recognized")
		}
	case "pk":
		// Load the public key
		key, err := ks.loadPublicKey(suffix, alias)
		if err != nil {
			return nil, fmt.Errorf("failed loading public key [%x] [%s]", ski, err)
		}

		switch k := key.(type) {
		// case *ecdsa.PublicKey:
		// 	return &ECDSAPublicKey{k}, nil
		case *sm2.PublicKey:
			return &SM2PublicKey{k}, nil
		default:
			return nil, errors.New("public key type not recognized")
		}
	default:
		return ks.searchKeystoreForSKI(ski)
	}
}

// StoreKey stores the key k in this KeyStore.
// If this KeyStore is read only then the method will fail.
// 将密钥/公私钥存入keystore
func (ks *fileBasedKeyStore) StoreKey(k bccsp.Key) (err error) {
	if ks.readOnly {
		return errors.New("read only KeyStore")
	}

	if k == nil {
		return errors.New("invalid key. It must be different from nil")
	}
	switch kk := k.(type) {
	case *SM2PrivateKey:
		err = ks.storePrivateKey("sk", hex.EncodeToString(k.SKI()), kk.privKey)
		if err != nil {
			return fmt.Errorf("failed storing SM2 private key [%s]", err)
		}

	case *SM2PublicKey:
		err = ks.storePublicKey("pk", hex.EncodeToString(k.SKI()), kk.pubKey)
		if err != nil {
			return fmt.Errorf("failed storing SM2 public key [%s]", err)
		}

	case *SM4Key:
		err = ks.storeKey("key", hex.EncodeToString(k.SKI()), kk.privKey)
		if err != nil {
			return fmt.Errorf("failed storing SM4 key [%s]", err)
		}

	// case *ECDSAPrivateKey:
	// 	err = ks.storePrivateKey("ecdsask", hex.EncodeToString(k.SKI()), kk.privKey)
	// 	if err != nil {
	// 		return fmt.Errorf("failed storing ECDSA private key [%s]", err)
	// 	}

	// case *ECDSAPublicKey:
	// 	err = ks.storePublicKey("ecdsapk", hex.EncodeToString(k.SKI()), kk.pubKey)
	// 	if err != nil {
	// 		return fmt.Errorf("failed storing ECDSA public key [%s]", err)
	// 	}

	// case *AESPrivateKey:
	// 	err = ks.storeKey("aeskey", hex.EncodeToString(k.SKI()), kk.privKey)
	// 	if err != nil {
	// 		return fmt.Errorf("failed storing AES key [%s]", err)
	// 	}

	default:
		return fmt.Errorf("key type not reconigned [%s]", k)
	}

	return
}

// 根据ski查找key，仅在alias找不到对应后缀目录时使用。
// 默认直接存储在path目录下，遍历path下的直接子文件，按照sm2或ecdsa私钥读取，并比较ski是否匹配。
func (ks *fileBasedKeyStore) searchKeystoreForSKI(ski []byte) (k bccsp.Key, err error) {

	files, _ := ioutil.ReadDir(ks.path)
	for _, f := range files {
		if f.IsDir() {
			continue
		}

		if f.Size() > (1 << 16) { //64k, somewhat arbitrary limit, considering even large keys
			continue
		}

		raw, err := ioutil.ReadFile(filepath.Join(ks.path, f.Name()))
		if err != nil {
			continue
		}
		// 尝试将pem转为sm2私钥
		key, err := pemToSm2PrivateKey(raw, ks.pwd)
		if err != nil {
			continue
		}

		// switch kk := key.(type) {
		// case *ecdsa.PrivateKey:
		// 	k = &ECDSAPrivateKey{kk}
		// case *sm2.PrivateKey:
		// 	k = &SM2PrivateKey{kk}
		// default:
		// 	continue
		// }
		k := &SM2PrivateKey{key}

		if !bytes.Equal(k.SKI(), ski) {
			continue
		}

		return k, nil
	}
	return nil, fmt.Errorf("key with SKI %x not found in %s", ski, ks.path)
}

// 根据alias获取对应的后缀
func (ks *fileBasedKeyStore) getSuffix(alias string) string {
	// 读取到path下的存储子目录
	files, _ := ioutil.ReadDir(ks.path)
	for _, f := range files {
		// alias作为前缀过滤
		if strings.HasPrefix(f.Name(), alias) {
			// 获取子目录名的后缀
			if strings.HasSuffix(f.Name(), "sk") {
				return "sk"
			}
			// if strings.HasSuffix(f.Name(), "ecdsask") {
			// 	return "ecdsask"
			// }
			if strings.HasSuffix(f.Name(), "pk") {
				return "pk"
			}
			// if strings.HasSuffix(f.Name(), "ecdsapk") {
			// 	return "ecdsapk"
			// }
			if strings.HasSuffix(f.Name(), "key") {
				return "key"
			}
			// if strings.HasSuffix(f.Name(), "aeskey") {
			// 	return "aeskey"
			// }
			break
		}
	}
	return ""
}

// 存储私钥
func (ks *fileBasedKeyStore) storePrivateKey(suffix, alias string, privateKey interface{}) error {
	// 将私钥转为pem字节流
	rawKey, err := privateKeyToPEM(privateKey, ks.pwd)
	if err != nil {
		logger.Errorf("Failed converting private key to PEM [%s]: [%s]", alias, err)
		return err
	}
	// 写入keystore存储目录 ${path}/${alias}_${suffix}
	err = ioutil.WriteFile(ks.getPathForAlias(alias, suffix), rawKey, 0600)
	if err != nil {
		logger.Errorf("Failed storing private key [%s]: [%s]", alias, err)
		return err
	}

	return nil
}

// 存储公钥
func (ks *fileBasedKeyStore) storePublicKey(suffix, alias string, publicKey interface{}) error {
	// 将公钥转为pem字节流
	rawKey, err := publicKeyToPEM(publicKey, ks.pwd)
	if err != nil {
		logger.Errorf("Failed converting public key to PEM [%s]: [%s]", alias, err)
		return err
	}
	// 写入keystore存储目录 ${path}/${alias}_${suffix}
	err = ioutil.WriteFile(ks.getPathForAlias(alias, suffix), rawKey, 0600)
	if err != nil {
		logger.Errorf("Failed storing private key [%s]: [%s]", alias, err)
		return err
	}

	return nil
}

// 存储密钥
func (ks *fileBasedKeyStore) storeKey(suffix, alias string, key []byte) error {
	//pem, err := aesToEncryptedPEM(key, ks.pwd)
	if len(ks.pwd) == 0 {
		ks.pwd = nil
	}
	// 密钥转为pem字节流
	// var pem []byte
	// var err error
	// switch suffix {
	// case "aeskey":
	// 	pem, err = aesToEncryptedPEM(key, ks.pwd)
	// case "sm4key":
	// 	pem, err = sm4ToEncryptedPEM(key, ks.pwd)
	// default:
	// 	pem, err = sm4.WriteKeytoMem(key, ks.pwd)
	// }
	pem, err := sm4ToEncryptedPEM(key, ks.pwd)

	if err != nil {
		logger.Errorf("Failed converting key to PEM [%s]: [%s]", alias, err)
		return err
	}
	// 写入keystore存储目录 ${path}/${alias}_${suffix}
	err = ioutil.WriteFile(ks.getPathForAlias(alias, suffix), pem, 0600)
	if err != nil {
		logger.Errorf("Failed storing key [%s]: [%s]", alias, err)
		return err
	}

	return nil
}

// 读取私钥
func (ks *fileBasedKeyStore) loadPrivateKey(suffix, alias string) (interface{}, error) {
	path := ks.getPathForAlias(alias, suffix)
	logger.Debugf("Loading private key [%s] at [%s]...", alias, path)

	raw, err := ioutil.ReadFile(path)
	if err != nil {
		logger.Errorf("Failed loading private key [%s]: [%s].", alias, err.Error())

		return nil, err
	}
	// 将pem字节流转为私钥
	// var privateKey interface{}
	// switch suffix {
	// case "sm2sk":
	// 	privateKey, err = pemToSm2PrivateKey(raw, ks.pwd)
	// case "ecdsask":
	// 	privateKey, err = pemToEcdsaPrivateKey(raw, ks.pwd)
	// default:
	// 	logger.Errorf("suffix not support : [%s]", suffix)
	// }

	// privateKey, err := pemToPrivateKey(raw, ks.pwd)
	// privateKey, err := x509.ReadPrivateKeyFromMem(raw, ks.pwd)
	privateKey, err := pemToSm2PrivateKey(raw, ks.pwd)
	if err != nil {
		logger.Errorf("Failed parsing private key [%s]: [%s].", alias, err.Error())
		return nil, err
	}
	return privateKey, nil
}

// 读取公钥
func (ks *fileBasedKeyStore) loadPublicKey(suffix, alias string) (interface{}, error) {
	path := ks.getPathForAlias(alias, suffix)
	logger.Debugf("Loading public key [%s] at [%s]...", alias, path)

	raw, err := ioutil.ReadFile(path)
	if err != nil {
		logger.Errorf("Failed loading public key [%s]: [%s].", alias, err.Error())

		return nil, err
	}
	// var pubKey interface{}
	// switch suffix {
	// case "sm2pk":
	// 	pubKey, err = pemToSm2PublicKey(raw, ks.pwd)
	// case "ecdsapk":
	// 	pubKey, err = pemToEcdsaPublicKey(raw, ks.pwd)
	// default:
	// 	logger.Errorf("suffix not support : [%s]", suffix)
	// }
	//privateKey, err := pemToPublicKey(raw, ks.pwd)
	// privateKey, err := x509.ReadPublicKeyFromMem(raw, ks.pwd)
	pubKey, err := pemToSm2PublicKey(raw, ks.pwd)
	if err != nil {
		logger.Errorf("Failed parsing private key [%s]: [%s].", alias, err.Error())
		return nil, err
	}
	return pubKey, nil
}

// 读取密钥
func (ks *fileBasedKeyStore) loadKey(suffix, alias string) ([]byte, error) {
	path := ks.getPathForAlias(alias, suffix)
	logger.Debugf("Loading key [%s] at [%s]...", alias, path)

	pem, err := ioutil.ReadFile(path)
	if err != nil {
		logger.Errorf("Failed loading key [%s]: [%s].", alias, err.Error())

		return nil, err
	}

	//key, err := pemToAES(pem, ks.pwd)
	if len(ks.pwd) == 0 {
		ks.pwd = nil
	}
	key, err := pemToSM4(pem, ks.pwd)
	// var key []byte
	// switch suffix {
	// case "aeskey":
	// 	key, err = pemToAES(pem, ks.pwd)
	// case "sm4key":
	// 	key, err = pemToSM4(pem, ks.pwd)
	// default:
	// 	key, err = sm4.ReadKeyFromMem(pem, ks.pwd)
	// }

	if err != nil {
		logger.Errorf("Failed parsing key [%s]: [%s]", alias, err)
		return nil, err
	}
	return key, nil
}

func (ks *fileBasedKeyStore) createKeyStore() error {
	// Create keystore directory root if it doesn't exist yet
	ksPath := ks.path
	logger.Debugf("Creating KeyStore at [%s]...", ksPath)

	err := os.MkdirAll(ksPath, 0755)
	if err != nil {
		return err
	}

	logger.Debugf("KeyStore created at [%s].", ksPath)
	return nil
}

func (ks *fileBasedKeyStore) openKeyStore() error {
	if ks.isOpen {
		return nil
	}
	ks.isOpen = true
	logger.Debugf("KeyStore opened at [%s]...done", ks.path)

	return nil
}

func (ks *fileBasedKeyStore) getPathForAlias(alias, suffix string) string {
	return filepath.Join(ks.path, alias+"_"+suffix)
}

func dirExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func dirEmpty(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	_, err = f.Readdir(1)
	if err == io.EOF {
		return true, nil
	}
	return false, err
}
