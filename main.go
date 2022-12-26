package main

import (
	"fmt"
	"github.com/golevi/forget/internal/encryption"
)

// scrypt settings

func main() {
	password := "password"
	encryptedText, salt, nonce, err := encryption.Encrypt(password, "Hello World..")
	if err != nil {
		panic(err.Error())
	}

	fmt.Println("ENCRYPTED")
	fmt.Println(encryptedText, nonce, salt)
	fmt.Println()
	fmt.Println("DECRYPTED")

	plaintext, err := encryption.Decrypt(password, salt, nonce, encryptedText)
	if err != nil {
		panic(err.Error())
	}

	fmt.Println(plaintext)
}
