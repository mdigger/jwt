package jwt

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"hash"
)

// Signer описывает информацию для подписи токена.
type Signer struct {
	hash hash.Hash // алгоритм генерации подписи
	name string    // название алгоритма
}

// NewSigner возвращает инициализированный подписчик токена, основанный на алгоритме SHA256.
func NewSignerHS256(key []byte) *Signer {
	return &Signer{
		hash: hmac.New(sha256.New, key),
		name: "HS256",
	}
}

// NewSignerHS384 возвращает инициализированный подписчик токена, основанный на алгоритме SHA384.
func NewSignerHS384(key []byte) *Signer {
	return &Signer{
		hash: hmac.New(sha512.New384, key),
		name: "HS384",
	}
}

// NewSignerHS512 возвращает инициализированный подписчик токена, основанный на алгоритме SHA512.
func NewSignerHS512(key []byte) *Signer {
	return &Signer{
		hash: hmac.New(sha512.New, key),
		name: "HS512",
	}
}

// Sign возвращает подписанный токен.
func (s Signer) Sign(token []byte) []byte {
	// кодируем в строку и объединяем с заголовком
	data := make([]byte, base64.RawURLEncoding.EncodedLen(len(token)))
	base64.RawURLEncoding.Encode(data, token)
	data = append(append(getHeader(s.name), '.'), data...)
	s.hash.Reset()     // сбрасываем состояние
	s.hash.Write(data) // добавляем содержимое токена для подсчета
	// добавляем к токену подпись и возвращаем сам токен
	sign := make([]byte, base64.RawURLEncoding.EncodedLen(s.hash.Size()))
	base64.RawURLEncoding.Encode(sign, s.hash.Sum(nil))
	return append(append(data, '.'), sign...)
}

// Parse разбирает токен и возвращает его содержимое.
func (s Signer) Parse(token []byte) ([]byte, error) {
	parts := bytes.SplitN(token, []byte{'.'}, 3) // разделяем токен на составные части
	if len(parts) != 3 {
		return nil, errors.New("bad token parts")
	}
	// декодируем заголовок
	data := make([]byte, base64.RawURLEncoding.DecodedLen(len(parts[0])))
	n, err := base64.RawURLEncoding.Decode(data, parts[0])
	if err != nil {
		return nil, err
	}
	header, err := parseHeader(data[:n]) // разбираем заголовок токена
	if err != nil {
		return nil, err
	}
	if header.Typ != "" && header.Typ != tokenName {
		return nil, errors.New("bad token type")
	}
	if header.Alg != s.name {
		return nil, errors.New("bad token sign algorithm")
	}
	// декодируем подпись
	data = make([]byte, s.hash.Size())
	if _, err := base64.RawURLEncoding.Decode(data, parts[2]); err != nil {
		return nil, err
	}
	s.hash.Reset() // сбрасываем состояние
	// считаем контрольную сумму токена, включая заголовок и содержимое
	if _, err := s.hash.Write(token[:len(parts[0])+len(parts[1])+1]); err != nil {
		return nil, err // ошибка подсчета подписи
	}
	if !hmac.Equal(s.hash.Sum(nil), data) { // сравниваем подписи
		return nil, errors.New("bad token sign")
	}
	// декодируем и возвращаем содержимое токена
	data = make([]byte, base64.RawURLEncoding.DecodedLen(len(parts[1])))
	n, err = base64.RawURLEncoding.Decode(data, parts[1])
	if err != nil {
		return nil, err
	}
	return data[:n], nil
}
