package encryption

import (
	"crypto/aes"
	"crypto/cipher"
)

func Decrypt(password []byte, c Cipher, key Keyer) ([]byte, error) {
	cipherKey, err := key(password, c.Salt)
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

	plaintext, err := aesgcm.Open(nil, c.Nonce, c.Payload, nil)
	if err != nil {
		return []byte{}, nil
	}

	return plaintext, nil
}
