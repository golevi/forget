package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/golevi/forget/internal/encoding"
)

const (
	saltByteSize = 8
	nonceSize    = 12
)

type Keyer func(password, salt string) ([]byte, error)

func Encrypt(password, plaintext string, key Keyer) (string, string, string, error) {
	salt, err := randomBytes(saltByteSize)
	if err != nil {
		return "", "", "", err
	}

	cipherKey, err := key(password, encoding.Encode(salt))
	if err != nil {
		return "", "", "", err
	}

	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return "", "", "", err
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", "", err
	}

	ciphertext := aesgcm.Seal(nil, nonce, []byte(plaintext), nil)

	return encoding.Encode(ciphertext), encoding.Encode(salt), encoding.Encode(nonce), nil
}

func randomBytes(x int) ([]byte, error) {
	b := make([]byte, x)

	_, err := rand.Read(b)
	if err != nil {
		return []byte{}, err
	}

	return b, nil
}
