package main

import (
	"fmt"

	"github.com/golevi/forget/internal/encryption"
	"github.com/golevi/forget/internal/key"
)

// scrypt settings

func main() {
	password := "password"
	encryptedText, salt, nonce, err := encryption.Encrypt(password, "Hello World..", key.Argon)
	if err != nil {
		panic(err.Error())
	}

	fmt.Println("ENCRYPTED")
	fmt.Println(encryptedText, nonce, salt)
	fmt.Println()
	fmt.Println("DECRYPTED")

	plaintext, err := encryption.Decrypt(password, salt, nonce, encryptedText, key.Argon)
	if err != nil {
		panic(err.Error())
	}

	fmt.Println(plaintext)
}
