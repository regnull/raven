package main

import (
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

	reader := rand.Reader
	key, err := rsa.GenerateKey(reader, keySize)
	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}

	outFile, err := os.Create(fileName)
	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}
	defer outFile.Close()

	encoder := gob.NewEncoder(outFile)
	err = encoder.Encode(key)
	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}
}
