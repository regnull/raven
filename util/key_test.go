package util

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadKeyNoPassword(t *testing.T) {
	key, err := ReadKey("../test_key/test_key_no_pass.gob", nil)
	assert.Nil(t, err)
	assert.NotNil(t, key)
}

func TestReadKeyWithPassword(t *testing.T) {
	key, err := ReadKey("../test_key/test_key_12345.gob", func() (string, error) {
		return "12345", nil
	})
	assert.Nil(t, err)
	assert.NotNil(t, key)
}

func TestSerializeKeyGob(t *testing.T) {
	reader := rand.Reader
	key, err := rsa.GenerateKey(reader, 1024)
	assert.Nil(t, err)
	assert.NotNil(t, key)
	bytes, err := SerializeKeyGob(key)
	assert.Nil(t, err)
	assert.NotNil(t, key)
	assert.True(t, len(bytes) > 10)
}

func TestSerializeKeyPem(t *testing.T) {
	reader := rand.Reader
	key, err := rsa.GenerateKey(reader, 1024)
	assert.Nil(t, err)
	assert.NotNil(t, key)
	bytes, err := SerializeKeyPem(key)
	fmt.Printf("%s\n", string(bytes))
	assert.Nil(t, err)
	assert.NotNil(t, key)
	assert.True(t, len(bytes) > 10)
}
