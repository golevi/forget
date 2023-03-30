package encryption

import (
	"crypto/aes"
	"crypto/cipher"
)

func Decrypt(password, salt, nonce, ciphertext []byte, key Keyer) ([]byte, error) {
	cipherKey, err := key(password, salt)
	if err != nil {
		return []byte{}, err
	}

	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return []byte{}, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return []byte{}, err
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return []byte{}, nil
	}

	return plaintext, nil
}
