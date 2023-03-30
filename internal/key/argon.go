package key

import (
	"golang.org/x/crypto/argon2"
)

const (
	argonTime    = 3
	argonMemory  = 32 * 1024
	argonThreads = 4
)

func Argon(password, salt []byte) ([]byte, error) {
	return argon2.IDKey(password, salt, argonTime, argonMemory, argonThreads, keyLen), nil
}
