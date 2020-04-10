package main

import (
	"crypto/aes"
	"crypto/cipher"
	"io/ioutil"
)

func decrypt() {
	key := []byte("0123456789abcdef0123456789abcdef")
	iv := []byte("123456788765")

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext, err := ioutil.ReadFile("./test.aes")
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	err = ioutil.WriteFile("./result.txt", plaintext, 0644)
	if err != nil {
		panic(err.Error())
	}
}

func main() {
	decrypt()
}
