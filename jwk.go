package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
)

var (
	// RSAKeyBits содержит длину ключа для генерации RSA. Используется в
	// функции NewRS256Key.
	RSAKeyBits = 2048
	// ECDSACurve содержит инициализированный elliptic.Curve для генерации
	// ECDSA ключа. Используется в функции NewES256Key.
	ECDSACurve = elliptic.P256()
)

// NewRS256Key возвращает новый ключ для подписи в формате RS256.
// Длина ключа задается переменной RSAKeyBits.
//
// Вызывает panic в случае ошибки создания.
func NewRS256Key() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, RSAKeyBits)
	if err != nil {
		panic(err)
	}
	return key
}

// NewES256Key возвращает новый ключ для подписи в формате ESxxx. По умолчанию
// возвращается ES256 ключ, но это можно изменить через переменную ECDSACurve.
//
// Вызывает panic в случае ошибки создания.
func NewES256Key() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(ECDSACurve, rand.Reader)
	if err != nil {
		panic(err)
	}
	return key
}
