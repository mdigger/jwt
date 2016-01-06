package jwt

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"hash"
)

const tokenName = "JWT"

// header описывает заголовок токена с информацией о подписи.
type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// getHeader возвращает сгенерированный заголовок токена с указанием алгоритма для подписи.
func getHeader(alg string) string {
	data, _ := json.Marshal(header{
		Alg: alg,
		Typ: tokenName,
	})
	return base64.RawURLEncoding.EncodeToString(data)
}

// Signer описывает информацию для подписи токена.
type Signer struct {
	hash   hash.Hash // алгоритм генерации подписи
	name   string    // название алгоритма
	header string    // сформированный заголовок токена для данного алгоритма
}

// NewSignerHS256 возвращает инициализированный подписчик токена.
func NewSignerHS256(key []byte) *Signer {
	return &Signer{
		hash:   hmac.New(sha256.New, key),
		name:   "HS256",
		header: getHeader("HS256"),
	}
}

var tokenDivider = []byte{'.'} // разделитель частей токена

// Sign возвращает подписанный токен.
func (s Signer) Sign(token []byte) []byte {
	// кодируем в строку и объединяем с заголовком
	data := make([]byte, base64.RawURLEncoding.EncodedLen(len(token)))
	base64.RawURLEncoding.Encode(data, token)
	data = append(append([]byte(s.header), '.'), data...)
	s.hash.Reset()     // сбрасываем состояние
	s.hash.Write(data) // добавляем содержимое токена для подсчета
	// добавляем к токену подпись и возвращаем сам токен
	sign := make([]byte, base64.RawURLEncoding.EncodedLen(s.hash.Size()))
	base64.RawURLEncoding.Encode(sign, s.hash.Sum(nil))
	return append(append(data, '.'), sign...)
}

// Parse разбирает токен и возвращает его содержимое.
func (s Signer) Parse(token []byte) ([]byte, error) {
	parts := bytes.SplitN(token, tokenDivider, 3) // разделяем токен на составные части
	if len(parts) != 3 {
		return nil, errors.New("bad token parts")
	}
	// декодируем заголовок
	data := make([]byte, base64.RawURLEncoding.DecodedLen(len(parts[0])))
	n, err := base64.RawURLEncoding.Decode(data, parts[0])
	if err != nil {
		return nil, err
	}
	data = data[:n]
	var header header // разбираем заголовок токена
	if err := json.Unmarshal(data, &header); err != nil {
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
