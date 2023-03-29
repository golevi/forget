package key

import (
	"github.com/golevi/forget/internal/encoding"
	"golang.org/x/crypto/scrypt"
)

const (
	scryptN = 1 << 15
	scryptR = 8
	scryptP = 1
)

func Scrypt(password, salt string) ([]byte, error) {
	byteSalt, err := encoding.Decode(salt)
	if err != nil {
		return []byte{}, nil
	}

	return scrypt.Key([]byte(password), byteSalt, scryptN, scryptR, scryptP, keyLen)
}
