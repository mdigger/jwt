package jwt

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Verify проверяет подпись токена. В качестве параметра передается ключ для
// проверки подписи или функция, принимающая одно или два строковых значения
// (алгоритм и идентификатор ключа) и возвращающая для них ключ.
//
// Сам ключ может быть в указан в следующих форматах:
//
// 	*rsa.PrivateKey
// 	*rsa.PublicKey
// 	*ecdsa.PrivateKey
// 	*ecdsa.PublicKey
// 	string
// 	[]byte
// 	fmt.Stringer
//
// Так же поддерживаются следующие форматы функции для передачи ключа:
// 	func(keyID string, alg string) interface{}
// 	func(keyID string, alg string) crypto.PublicKey
// 	func(keyID string, alg string) []byte
// 	func(keyID string) interface{}
// 	func(keyID string) crypto.PublicKey
// 	func(keyID string) []byte
func Verify(token string, key interface{}) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("invalid token")
	}
	// разбираем заголовок токена
	data, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return err
	}
	var header = new(struct {
		Algorithm string `json:"alg"`           // алгоритм подписи
		Type      string `json:"typ"`           // тип токена
		KeyID     string `json:"kid,omitempty"` // необязательный идентификатор ключа
	})
	if err := json.Unmarshal(data, header); err != nil {
		return err
	}
	// проверяем тип токена
	if header.Type != "" && header.Type != "JWT" {
		return errors.New("bad token type")
	}
	if len(parts[2]) == 0 {
		return errors.New("token not signed")
	}
	// если для получения ключа задана функция, то вызываем ее
	switch fkey := key.(type) {
	case nil:
		return nil // проверка не требуется
	case func(string, string) interface{}:
		key = fkey(header.Algorithm, header.KeyID)
	case func(string, string) crypto.PublicKey:
		key = fkey(header.Algorithm, header.KeyID)
	case func(string, string) []byte:
		key = fkey(header.Algorithm, header.KeyID)
	case func(string) interface{}:
		key = fkey(header.Algorithm)
	case func(string) crypto.PublicKey:
		key = fkey(header.Algorithm)
	case func(string) []byte:
		key = fkey(header.Algorithm)
	}
	if key == nil {
		return errors.New("empty token sign key")
	}
	// декодируем подпись
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}
	// возвращаем результат проверки подписи токена
	return verify([]byte(fmt.Sprintf("%s.%s", parts[0], parts[1])),
		signature, key)
}
