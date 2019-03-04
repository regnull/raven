package util

import (
	"bytes"
	"crypto/rsa"
	"encoding/gob"
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
		return nil, fmt.Errorf("error reading file %s, %s\n", fileName, err)
	}

	buf := make([]byte, maxFileSize)
	n, err := file.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("error reading file %s, %s\n", fileName, err)
	}
	if n == 0 {
		return nil, fmt.Errorf("zero bytes read\n")
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
		return nil, fmt.Errorf("error deserializing the key: %s\n", err)
	}

	err = key.Validate()
	if err != nil {
		return nil, fmt.Errorf("validation failed: %s\n", err)
	}
	return &key, nil
}
