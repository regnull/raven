package main

import (
	"bytes"
	"crypto/rsa"
	"encoding/gob"
	"flag"
	"fmt"
	"os"

	"github.com/regnull/raven/util"
)

const (
	maxFileSize = 1024 * 10
)

func main() {
	var fileName string
	flag.StringVar(&fileName, "file", "", "key file name")
	flag.Parse()

	if fileName == "" {
		fmt.Printf("--file must be specified")
		os.Exit(1)
	}

	// Open file and read content.
	file, err := os.Open(fileName)
	if err != nil {
		fmt.Printf("error reading file %s, %s\n", fileName, err)
		os.Exit(1)
	}

	buf := make([]byte, maxFileSize)
	n, err := file.Read(buf)
	if err != nil {
		fmt.Printf("error reading file %s, %s\n", fileName, err)
		os.Exit(1)
	}
	if n == 0 {
		fmt.Printf("zero bytes read\n")
		os.Exit(1)
	}
	buf = buf[:n]

	// Password-decrypt the content.
	password, err := util.ReadPassword()
	fmt.Printf("\n")
	var keyBytes []byte
	if password != "" {
		passwordEncryptionKey := util.KeyFromString(password)
		keyBytes, err = util.Decrypt(buf, passwordEncryptionKey)
		if err != nil {
			fmt.Printf("decryption failed: %s\n", err)
			os.Exit(1)
		}
	} else {
		keyBytes = buf
	}

	// Deserialize and verify.
	reader := gob.NewDecoder(bytes.NewReader(keyBytes))
	var key rsa.PrivateKey
	err = reader.Decode(&key)
	if err != nil {
		fmt.Printf("error deserializing the key: %s\n", err)
		os.Exit(1)
	}

	err = key.Validate()
	if err != nil {
		fmt.Printf("validation failed: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("key validated\n")
}
