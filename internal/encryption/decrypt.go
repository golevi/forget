package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"github.com/golevi/forget/internal/encoding"
	"github.com/golevi/forget/internal/key"
)

func Decrypt(password, salt, nonce, ciphertext string) (string, error) {
	cipherKey, err := key.Create(password, salt)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	byteNonce, err := encoding.Decode(nonce)
	if err != nil {
		return "", err
	}

	ct, err := encoding.Decode(ciphertext)
	if err != nil {
		return "", err
	}

	plaintext, err := aesgcm.Open(nil, byteNonce, ct, nil)
	if err != nil {
		return "", nil
	}

	return string(plaintext), nil
}
