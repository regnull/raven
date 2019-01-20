package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"

	"crypto/rand"
	"crypto/rsa"

	"encoding/gob"
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
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}

	password, err := util.ReadPassword()

	// Write output to the file.
	outFile, err := os.Create(fileName)
	if err != nil {
		fmt.Printf("can't open file %s, %s\n", fileName, err)
		os.Exit(1)
	}
	defer outFile.Close()
	n, err := outFile.Write(buf.Bytes())
	if err != nil {
		fmt.Printf("error writing to output file: %s\n", err)
		os.Exit(1)
	}
	if n < keySize {
		fmt.Printf("file size is too small, %d\n", n)
		os.Exit(1)
	}
}
