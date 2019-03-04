package main

import (
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

	key, err := util.ReadKey(fileName, func() (string, error) {
		password, err := util.ReadPassword()
		fmt.Printf("\n")
		return password, err
	})
	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(1)
	}

	err = key.Validate()
	if err != nil {
		fmt.Printf("validation failed: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("key validated\n")
}
