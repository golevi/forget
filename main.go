package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"

	"github.com/golevi/forget/internal/encoding"
	"github.com/golevi/forget/internal/encryption"
	"github.com/golevi/forget/internal/key"
)

// scrypt settings

func main() {
	f, _ := os.Open("./lorem.txt")
	text, _ := io.ReadAll(f)

	password := make([]byte, 32)
	rand.Read(password)

	// password := []byte("password")
	encryptedText, salt, nonce, err := encryption.Encrypt(password, text, key.Argon)
	if err != nil {
		panic(err.Error())
	}

	fmt.Printf("Secret: %s\nCipher: %s\nNonce : %s\nSalt  : %s\n", encoding.Encode(password), encoding.Encode(encryptedText), encoding.Encode(nonce), encoding.Encode(salt))

	plaintext, err := encryption.Decrypt(password, salt, nonce, encryptedText, key.Argon)
	if err != nil {
		panic(err.Error())
	}

	fmt.Printf("%s\n", plaintext)
}
