package tools

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"testing"
)

func TestFileBasedKeyStore(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		os.RemoveAll(tmpDir)
	}()
	t.Log("Temp dir: ", tmpDir)

	if err = generateRSAKeyPairInDir(tmpDir, "default"); err != nil {
		t.Fatal(err)
	}

	if err = generateRSAKeyPairInDir(tmpDir, "system"); err != nil {
		t.Fatal(err)
	}

	keyStore, err := NewFileKeyStore(map[string]string{
		"system":  path.Join(tmpDir, "system"),
		"default": path.Join(tmpDir, "default"),
	})

	if err != nil {
		t.Fatal(err)
	}

	key, err := keyStore.GetPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if key == nil {
		t.Fatal("key was not defined")
	}

	key, err = keyStore.GetPrivateKeyByName("system")
	if err != nil {
		t.Fatal(err)
	}
	if key == nil {
		t.Fatal("key was not defined")
	}
}

func TestDirBasedKeyStore(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		os.RemoveAll(tmpDir)
	}()

	if err = generateRSAKeyPairInDir(tmpDir, "default"); err != nil {
		t.Fatal(err)
	}

	if err = generateRSAKeyPairInDir(tmpDir, "system"); err != nil {
		t.Fatal(err)
	}

	keyStore, err := NewDirKeyStore(tmpDir)

	if err != nil {
		t.Fatal(err)
	}

	key, err := keyStore.GetPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if key == nil {
		t.Fatal("key was not defined")
	}

	key, err = keyStore.GetPrivateKeyByName("system")
	if err != nil {
		t.Fatal(err)
	}
	if key == nil {
		t.Fatal("key was not defined")
	}
}

func generateRSAKeyPairInDir(dir string, keyFileName string) error {
	keyPair, err := generateRSAKeyPair()
	if err != nil {
		return err
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&keyPair.PublicKey) //asn1.Marshal(keyPair.PublicKey)

	if err != nil {
		return err
	}

	pubPemKey := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	privPemKey := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(keyPair),
	}

	pubKeyFile, err := os.Create(fmt.Sprintf("%s/%s.pub", dir, keyFileName))
	if err != nil {
		return err
	}
	privKeyFile, err := os.Create(fmt.Sprintf("%s/%s", dir, keyFileName))
	if err != nil {
		return err
	}

	err = pem.Encode(pubKeyFile, pubPemKey)
	if err != nil {
		return err
	}
	err = pem.Encode(privKeyFile, privPemKey)
	if err != nil {
		return err
	}

	return nil
}

func generateRSAKeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}
