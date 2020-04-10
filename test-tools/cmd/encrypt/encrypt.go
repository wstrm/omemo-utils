package main

import (
	"crypto/aes"
	"crypto/cipher"
	"io/ioutil"
)

func encrypt() {
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

	plaintext, err := ioutil.ReadFile("./test.txt")
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, iv, plaintext, nil)

	err = ioutil.WriteFile("./test.aes", ciphertext, 0644)
	if err != nil {
		panic(err.Error())
	}
}

func main() {
	encrypt()
}
