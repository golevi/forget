package key

import (
	"github.com/golevi/forget/internal/encoding"
	"golang.org/x/crypto/argon2"
)

const (
	argonTime    = 3
	argonMemory  = 32 * 1024
	argonThreads = 4
)

func Argon(password, salt string) ([]byte, error) {
	byteSalt, err := encoding.Decode(salt)
	if err != nil {
		return []byte{}, nil
	}

	return argon2.Key([]byte(password), byteSalt, argonTime, argonMemory, argonThreads, keyLen), nil
}
