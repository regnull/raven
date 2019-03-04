package util

import (
	"bufio"
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/gob"
	"encoding/pem"
	"fmt"
	"os"
)

const (
	maxFileSize = 1024 * 10
)

type PasswordFunc func() (string, error)

// ReadKey reads the key from file. It accepts the name of the password file and
// function to read the password.
func ReadKey(fileName string, pf PasswordFunc) (*rsa.PrivateKey, error) {
	// Open file and read content.
	file, err := os.Open(fileName)
	if err != nil {
		return nil, fmt.Errorf("error reading file %s, %s", fileName, err)
	}

	buf := make([]byte, maxFileSize)
	n, err := file.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("error reading file %s, %s", fileName, err)
	}
	if n == 0 {
		return nil, fmt.Errorf("zero bytes read")
	}
	buf = buf[:n]

	// Password-decrypt the content.
	password := ""
	if pf != nil {
		password, err = pf()
		if err != nil {
			return nil, err
		}
	}
	var keyBytes []byte
	if password != "" {
		passwordEncryptionKey := KeyFromString(password)
		keyBytes, err = Decrypt(buf, passwordEncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("decryption failed: %s\n", err)
		}
	} else {
		keyBytes = buf
	}

	// Deserialize and verify.
	reader := gob.NewDecoder(bytes.NewReader(keyBytes))
	var key rsa.PrivateKey
	err = reader.Decode(&key)
	if err != nil {
		return nil, fmt.Errorf("error deserializing the key: %s", err)
	}

	err = key.Validate()
	if err != nil {
		return nil, fmt.Errorf("validation failed: %s", err)
	}
	return &key, nil
}

// SerializeKeyGob serializes key using Gob format.
func SerializeKeyGob(key *rsa.PrivateKey) ([]byte, error) {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(key)
	if err != nil {
		return nil, fmt.Errorf("encoding failed: %s", err)
	}
	return buf.Bytes(), nil
}

// SerializeKeyPem serializes key using PEM format.
func SerializeKeyPem(key *rsa.PrivateKey) ([]byte, error) {
	var pemKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	var buf bytes.Buffer
	writer := bufio.NewWriter(&buf)
	err := pem.Encode(writer, pemKey)
	if err != nil {
		return nil, fmt.Errorf("encoding failed: %s", err)
	}
	writer.Flush()
	return buf.Bytes(), nil
}

// SerializePublicKeyPem serializes public key using PEM format.
func SerializePublicKeyPem(key *rsa.PublicKey) ([]byte, error) {
	asn1Bytes, err := asn1.Marshal(*key)
	if err != nil {
		return nil, fmt.Errorf("encoding failed: %s", err)
	}
	var pemKey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}
	var buf bytes.Buffer
	writer := bufio.NewWriter(&buf)
	err = pem.Encode(writer, pemKey)
	if err != nil {
		return nil, fmt.Errorf("encoding failed: %s", err)
	}
	writer.Flush()
	return buf.Bytes(), nil
}
