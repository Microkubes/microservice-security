package tools

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"strings"

	jwtgo "github.com/dgrijalva/jwt-go"
)

// KeyStore defines an interface for reading private keys for JWT signing.
// The keys may be loaded from file or from a repository, however the implementation
// must at least guarantee a basic level of caching.
type KeyStore interface {
	// GetPrivateKey returns the default private key used for signing.
	GetPrivateKey() (interface{}, error)
	// GetPrivateKeyByName gets a private key by name
	GetPrivateKeyByName(keyName string) (interface{}, error)
}

// FileKeyStore holds the data for a file-based KeyStore implementation.
type FileKeyStore struct {
	// PrivateKey is the default private key
	PrivateKey interface{}

	// KeysMap is a map <key-name>:<key-data>
	KeysMap map[string]interface{}
}

// GetPrivateKey returns the default private key. This key is also available
// under the name "default".
func (fks *FileKeyStore) GetPrivateKey() (interface{}, error) {
	if fks.PrivateKey != nil {
		return fks.PrivateKey, nil
	}
	return nil, fmt.Errorf("No default key loaded")
}

// GetPrivateKeyByName returns a private by by name. The key is looked up in the
// underlying map, and an error is raised if there is no key under the name requested.
func (fks *FileKeyStore) GetPrivateKeyByName(keyName string) (interface{}, error) {
	priv, ok := fks.KeysMap[keyName]
	if !ok {
		return nil, fmt.Errorf("no key with name %s loaded", keyName)
	}
	return priv, nil
}

// NewFileKeyStore returns a file-based KeyStore implementation.
// The keys are loaded based on the map of <key-name>:<key-file> provided.
// The functions expects to be at least one key with name "default" defined.
// The keys must be RSA keys and the files must be PEM.
func NewFileKeyStore(keyFiles map[string]string) (KeyStore, error) {
	keyStore := FileKeyStore{
		KeysMap: make(map[string]interface{}),
	}
	for keyName, keyFile := range keyFiles {
		keyBytes, err := ioutil.ReadFile(keyFile)
		if err != nil {
			return nil, err
		}
		privKey, err := jwtgo.ParseRSAPrivateKeyFromPEM(keyBytes)
		if err != nil {
			return nil, err
		}
		keyStore.KeysMap[keyName] = privKey
	}
	defaultKey, ok := keyStore.KeysMap["default"]
	if !ok {
		return nil, fmt.Errorf("no default key for signing client JWT tokens defined")
	}
	keyStore.PrivateKey = defaultKey
	return &keyStore, nil
}

// NewDirKeyStore returns a directory-based KeyStore implementation.
// The keys are loaded from the directory by scanning the directory
// for private keys.
// The functions expects to be at least one key with name "default" defined.
// The keys must be RSA keys and the files must be PEM.
func NewDirKeyStore(keysDir string) (KeyStore, error) {
	fi, err := os.Stat(keysDir)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsDir() {
		return nil, fmt.Errorf("directory must be provided")
	}
	files, err := ioutil.ReadDir(keysDir)
	if err != nil {
		return nil, err
	}
	keysMap := map[string]string{}
	for _, file := range files {
		if !file.IsDir() {
			name := file.Name()
			if suffix := hasAnySuffix(name, ".pub", ".pubk", ".pk"); suffix == nil {
				keysMap[name] = path.Join(keysDir, name)
			}
		}
	}
	return NewFileKeyStore(keysMap)
}

func hasAnySuffix(name string, suffixes ...string) *string {
	var suffix *string
	name = strings.ToLower(name)
	for _, sfx := range suffixes {
		if strings.HasSuffix(name, sfx) {
			suffix = &sfx
			break
		}
	}
	return suffix
}
