package key

import (
	"golang.org/x/crypto/scrypt"
)

const (
	scryptN = 1 << 15
	scryptR = 8
	scryptP = 1
)

func Scrypt(password, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, scryptN, scryptR, scryptP, keyLen)
}
