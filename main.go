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
	cipher, err := encryption.Encrypt(password, text, key.Argon)
	if err != nil {
		panic(err.Error())
	}

	fmt.Printf("Secret: %s\nCipher: %s\nNonce : %s\nSalt  : %s\n",
		encoding.Encode(password),
		encoding.Encode(cipher.Payload),
		encoding.Encode(cipher.Nonce),
		encoding.Encode(cipher.Salt),
	)

	plaintext, err := encryption.Decrypt(
		password, cipher, key.Argon,
	)
	if err != nil {
		panic(err.Error())
	}

	fmt.Printf("%s\n", plaintext)
}
