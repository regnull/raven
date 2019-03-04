package util

import (
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
