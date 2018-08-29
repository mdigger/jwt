package jwt

import (
	"crypto/ecdsa"
	"fmt"
	"testing"
)

func TestConfig(t *testing.T) {
	var conf = &Config{
		Issuer:   "http://service.example.com/",
		UniqueID: Nonce(8), // задаем функцию генерации случайного nonce
		Key:      NewES256Key(),
	}
	token, err := conf.Token(JSON{"sub": "9394203942934"})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("token:", token)
}

func TestConfigFuncKey(t *testing.T) {
	var keyFunc = func() *ecdsa.PrivateKey {
		return NewES256Key()
	}
	var conf = &Config{
		Issuer:   "http://service.example.com/",
		UniqueID: Nonce(8), // задаем функцию генерации случайного nonce
		Key:      keyFunc,
	}
	token, err := conf.Token(JSON{"sub": "9394203942934"})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("token:", token)
}
