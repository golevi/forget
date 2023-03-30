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

func Encrypt(password, plaintext []byte, key Keyer) (Cipher, error) {
	salt, err := randomBytes(saltByteSize)
	if err != nil {
		return Cipher{}, err
	}

	cipherKey, err := key(password, salt)
	if err != nil {
		return Cipher{}, err
	}

	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return Cipher{}, err
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return Cipher{}, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return Cipher{}, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, []byte(plaintext), nil)

	return Cipher{
		Payload: ciphertext,
		Salt:    salt,
		Nonce:   nonce,
	}, nil
}

func randomBytes(x int) ([]byte, error) {
	b := make([]byte, x)

	_, err := rand.Read(b)
	if err != nil {
		return []byte{}, err
	}

	return b, nil
}
