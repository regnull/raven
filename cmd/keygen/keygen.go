package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"

	"crypto/rand"
	"crypto/rsa"

	"encoding/gob"

	"github.com/regnull/raven/util"
)

func main() {
	var (
		keySize  int
		fileName string
	)

	flag.IntVar(&keySize, "size", 4096, "key size")
	flag.StringVar(&fileName, "file", "", "key file name")
	flag.Parse()

	if fileName == "" {
		fmt.Printf("--file must be specified\n")
		os.Exit(1)
	}

	// Generate the key.
	fmt.Printf("generating...\n")
	reader := rand.Reader
	key, err := rsa.GenerateKey(reader, keySize)
	if err != nil {
		fmt.Printf("key generation failed: %s\n", err)
		os.Exit(1)
	}

	// Write key bytes into a buffer.
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	err = encoder.Encode(key)
	if err != nil {
		fmt.Printf("encoding failed: %s\n", err)
		os.Exit(1)
	}

	// Encrypt with password.
	password, err := util.ReadPassword()
	fmt.Printf("\n")
	var outputBytes []byte
	if password != "" {
		passwordEncryptionKey := util.KeyFromString(password)
		outputBytes, err = util.Encrypt(buf.Bytes(), passwordEncryptionKey)
		if err != nil {
			fmt.Printf("encryption failed: %s\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Printf("WARNING: private key is not encrypted\n")
		outputBytes = buf.Bytes()
	}

	// Write output to the file.
	outFile, err := os.Create(fileName)
	if err != nil {
		fmt.Printf("can't open file %s, %s\n", fileName, err)
		os.Exit(1)
	}
	defer outFile.Close()
	n, err := outFile.Write(outputBytes)
	if err != nil {
		fmt.Printf("error writing to output file: %s\n", err)
		os.Exit(1)
	}
	if n == 0 {
		// This should probably never happen.
		fmt.Printf("zero bytes written")
		os.Exit(1)
	}
	fmt.Printf("key written to %s\n", fileName)
}
