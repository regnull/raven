package util

import (
	"crypto/rand"
	"crypto/rsa"
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
	assert.Nil(t, err)
	assert.NotNil(t, key)
	assert.True(t, len(bytes) > 10)
}

func TestSerializePublicKeyPem(t *testing.T) {
	reader := rand.Reader
	key, err := rsa.GenerateKey(reader, 1024)
	assert.Nil(t, err)
	assert.NotNil(t, key)
	bytes, err := SerializePublicKeyPem(&key.PublicKey)
	assert.Nil(t, err)
	assert.NotNil(t, key)
	assert.True(t, len(bytes) > 10)
}

func TestParsePemPublicKey(t *testing.T) {
	pemKey := `-----BEGIN PRIVATE KEY-----
MIICXQIBAAKBgQD4a49fRY1qqbcs5kIin4BIrwG4Z/Z3tJW1lzBYJ+xLQA9s7+BG
+xMeDmTuIgmH17SdLBWFe3AtW43Iyau/WP1065bdpYqsVbkh2v079wjPrDQQgfaK
xGFTTZbOI/wAgFn5olAVipNJesh75zpIKf4fUPIdehuzFW4OLLTba4GH7wIDAQAB
AoGBANK4MjJnRhCvC3DrlDfYQjHlOTlZ/mgF52PUbi6pFreyDCOkygKLoOjC3vxc
JOd0ooEbztmeHkZrPbaO0r+J1ds2zbBWLdk7MtfJ+nnZC5WCARZeWE5g82ExuCqg
o0JGmqexy19EV4PwjaqwnXN/HvnYfT5L/9EqeT67j0rzmL7xAkEA+YIyjnDNvJi/
wv2TxjB6lNpzvIH4LVeaGHoiX6DfYbM3Cd+gy8ulrU8kyQ4ZfLZA3HLUa9TuypZ7
DGUEX4zXmQJBAP7iHQGakLeVg1MfMEutP95N7XkYgUAxNhGT4p08iv7Oxtk1jDyq
MZxP6Xvd1M+h4AOYMMbZ9SVn2IL3S9ArcMcCQGWwUJaJFvCkeJMp8g42N99u4PiV
J+ai62TKcjPzRtd0yRu3DrvAdfeaZ+2hV3XiebDfBAAmumPKzL+SdCPVLRECQEXf
WrBL3QxW0m+BB05XqkCZAFbIHvaoBvh+oAsWw8vih6SYB1/CEGOXjJxGTca1y6Fw
oT6CFbAxbatJe+EPZ5UCQQCrtMixvobV3QHvbF7KwnEAzhgPek+LHu93zyrTaGAj
5FgMVtaiJcmDu8Q3ggudP/IEVgP9HJRgOMlX3S3vvgbe
-----END PRIVATE KEY-----`
	key, err := ParsePemPrivateKey([]byte(pemKey))
	assert.Nil(t, err)
	assert.Nil(t, key.Validate())
}
