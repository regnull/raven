package util

import (
	"encoding/hex"
	"io"

	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
)

// StringHash returns a hash of the string.
func StringHash(s string) string {
	h := md5.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

// KeyFromString returns a key generated from the given string.
func KeyFromString(s string) []byte {
	return []byte(StringHash(s))
}

// Encrypt encrypts data with the key, and returns encrypted data.
func Encrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, data, nil), nil
}

// Decrypt decrypts encrypted data using the provided key, and returns decrypted data.
func Decrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	nonce, encryptedData := data[:nonceSize], data[nonceSize:]
	decryptedData, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, err
	}
	return decryptedData, nil
}
