package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256" // импортируем явно для поддержки хеширования
	"errors"
	"fmt"
	"math/big"
)

// algorithm возвращает название алгоритма, используемого для подписи.
func algorithm(key interface{}) (string, crypto.Hash) {
	ecdsaParams := func(name string) (string, crypto.Hash) {
		switch name {
		case "P-256":
			return "ES256", crypto.SHA256
		case "P-384":
			return "ES384", crypto.SHA384
		case "P-521":
			return "ES512", crypto.SHA512
		default:
			return "", 0
		}
	}
	switch key := key.(type) {
	case *rsa.PrivateKey, *rsa.PublicKey, rsa.PrivateKey, rsa.PublicKey:
		return "RS256", crypto.SHA256
	case *ecdsa.PrivateKey:
		return ecdsaParams(key.Params().Name)
	case *ecdsa.PublicKey:
		return ecdsaParams(key.Params().Name)
	case []byte, string, fmt.Stringer:
		return "HS256", crypto.SHA256
	}
	return "none", 0
}

// sign подписывает данные указанным ключем и возвращает сигнатуру подписи.
// В качестве ключа можно указать *rsa.PrivateKey, *ecdsa.PrivateKey, []byte,
// string или любой объект, поддерживающий fmt.Stringer. В последних трех
// случаях для подписи будет использоваться алгоритм HS256.
func sign(data []byte, key crypto.PrivateKey) ([]byte, error) {
	_, hash := algorithm(key) // получаем алгоритм для хеширования данных
	if !hash.Available() {
		return nil, fmt.Errorf("unsupported hash for key type %T [%d]", key, hash)
	}
	// в зависимости от типа ключа используем разные алгоритмы
repeat:
	switch signerKey := key.(type) {
	case *rsa.PrivateKey:
		h := hash.New()
		h.Write(data)
		return signerKey.Sign(rand.Reader, h.Sum(nil), hash)

	case *ecdsa.PrivateKey:
		h := hash.New()
		h.Write(data)
		r, s, err := ecdsa.Sign(rand.Reader, signerKey, h.Sum(nil))
		if err != nil {
			return nil, err
		}
		rb, sb := r.Bytes(), s.Bytes()
		size := signerKey.Params().BitSize / 8
		if size%8 > 0 {
			size++
		}
		signature := make([]byte, size*2)
		copy(signature[size-len(rb):], rb)
		copy(signature[size*2-len(sb):], sb)
		return signature, nil

	case []byte:
		mac := hmac.New(hash.New, signerKey)
		mac.Write(data)
		return mac.Sum(nil), nil
	case string:
		key = []byte(signerKey)
		goto repeat
	case fmt.Stringer:
		key = []byte(signerKey.String())
		goto repeat

	default:
		return nil, fmt.Errorf("unsupported key type %T", key)
	}
}

// verify проверяет, что данные действительно подписаны данным ключем.
// В качестве ключа можно указать *rsa.PrivateKey, *rsa.PublicKey,
// *ecdsa.PrivateKey, *ecdsa.PublicKey, []byte, string или любой объект,
// поддерживающий fmt.Stringer. В последних трех случаях для проверки подписи
// будет использоваться алгоритм HS256.
func verify(data, signature []byte, key interface{}) error {
	_, hash := algorithm(key) // получаем алгоритм для хеширования данных
	if !hash.Available() {
		return fmt.Errorf("unsupported hash for key type %T [%d]", key, hash)
	}
	// в зависимости от типа ключа используем разные алгоритмы
repeat:
	switch signerKey := key.(type) {
	case *rsa.PublicKey: // проверяем подпись с публичным ключем RSA
		h := hash.New()
		h.Write(data)
		return rsa.VerifyPKCS1v15(signerKey, crypto.SHA256, h.Sum(nil), signature)
	case *rsa.PrivateKey: // подменяем ключ на публичный
		key = &signerKey.PublicKey
		goto repeat

	case *ecdsa.PublicKey: // выполняем проверку подписи ECDSA
		h := hash.New()
		h.Write(data)
		// восстанавливаем значения r и s из сигнатуры
		div := len(signature) / 2
		r := new(big.Int).SetBytes(signature[:div])
		s := new(big.Int).SetBytes(signature[div:])
		if !ecdsa.Verify(signerKey, h.Sum(nil), r, s) {
			return errors.New("bad ecdsa signature")
		}
		return nil
	case *ecdsa.PrivateKey: // подменяем ключ на публичный
		key = &signerKey.PublicKey
		goto repeat

	case []byte: // хешируем исходные данные и сравниваем с сохраненным хешом
		mac := hmac.New(hash.New, signerKey)
		mac.Write(data)
		signature2 := mac.Sum(nil)
		if !hmac.Equal(signature, signature2) {
			return errors.New("bad hmac signature")
		}
		return nil
	case string: // преобразуем формат ключа к бинарному и повторяем
		key = []byte(signerKey)
		goto repeat
	case fmt.Stringer: // преобразуем формат ключа к бинарному и повторяем
		key = []byte(signerKey.String())
		goto repeat

	default:
		return fmt.Errorf("unsupported key type %T", key)
	}
}
