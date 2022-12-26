package key

import (
	"github.com/golevi/forget/internal/encoding"
	"golang.org/x/crypto/scrypt"
)

const (
	N      = 1 << 15
	r      = 8
	p      = 1
	keyLen = 32
)

func Create(password, salt string) ([]byte, error) {
	byteSalt, err := encoding.Decode(salt)
	if err != nil {
		return []byte{}, nil
	}

	return scrypt.Key([]byte(password), byteSalt, N, r, p, keyLen)
}
