package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

const (
	saltByteSize = 8
	nonceSize    = 12
)

type Keyer func(password, salt []byte) ([]byte, error)

func Encrypt(password, plaintext []byte, key Keyer) ([]byte, []byte, []byte, error) {
	salt, err := randomBytes(saltByteSize)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, err
	}

	cipherKey, err := key(password, salt)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, err
	}

	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, err
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return []byte{}, []byte{}, []byte{}, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return []byte{}, []byte{}, []byte{}, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, []byte(plaintext), nil)

	return ciphertext, salt, nonce, nil
}

func randomBytes(x int) ([]byte, error) {
	b := make([]byte, x)

	_, err := rand.Read(b)
	if err != nil {
		return []byte{}, err
	}

	return b, nil
}
