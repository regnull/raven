package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStringHash(t *testing.T) {
	h := StringHash("foo")
	assert.Equal(t, "acbd18db4cc2f85cedef654fccc4a4d8", h)
}

func TestEncrypDecrypt(t *testing.T) {
	plaintext := "hi there"
	key := KeyFromString("foo")
	encrypted, err := Encrypt([]byte(plaintext), key)
	assert.Nil(t, err)
	assert.NotNil(t, encrypted)

	decrypted, err := Decrypt(encrypted, key)
	assert.Nil(t, err)
	assert.NotNil(t, decrypted)
	assert.Equal(t, plaintext, string(decrypted))
}
