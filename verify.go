package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
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
// 	func(keyID string) interface{}
//
// Кроме проверки подписи, проверяются основные даты токена, что он актуален
// на данный момент.
//
// Возвращается неразобранное содержимое токена.
func Verify(token string, key interface{}) (claim []byte, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalid
	}

	// разбираем основной раздел токена
	claim, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	times := new(struct {
		Created   Time `json:"iat"`
		Expires   Time `json:"exp"`
		NotBefore Time `json:"nbf"`
	})
	if err := json.Unmarshal(claim, times); err != nil {
		return nil, err
	}

	// проверяем поля со временем
	now := time.Now() // текущее время
	if !times.Created.IsZero() && times.Created.After(now) {
		return nil, ErrCreatedAfterNow
	}
	if !times.Expires.IsZero() && times.Expires.Before(now) {
		return nil, ErrExpired
	}
	if !times.NotBefore.IsZero() && times.NotBefore.After(now) {
		return nil, ErrNotBeforeNow
	}

	// разбираем заголовок токена
	data, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}

	header := new(struct {
		Algorithm string `json:"alg"`           // алгоритм подписи
		Type      string `json:"typ"`           // тип токена
		KeyID     string `json:"kid,omitempty"` // необязательный идентификатор ключа
	})
	if err := json.Unmarshal(data, header); err != nil {
		return nil, err
	}

	// проверяем тип токена
	if header.Type != "" && header.Type != "JWT" {
		return nil, ErrBadType
	}
	if len(parts[2]) == 0 {
		return nil, ErrNotSigned
	}

	// если для получения ключа задана функция, то вызываем ее
	switch fkey := key.(type) {
	case nil:
		return claim, nil // проверка не требуется
	case func(string, string) interface{}:
		key = fkey(header.Algorithm, header.KeyID)
	case func(string) interface{}:
		key = fkey(header.Algorithm)
	}

	if key == nil {
		return nil, ErrEmptySignKey
	} else if err, ok := key.(error); ok {
		return nil, err
	}

	// декодируем подпись
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}

	// проверяем подпись токена
	withoutSignature := token[:len(parts[0])+len(parts[1])+1]
	if err = verify([]byte(withoutSignature), signature, key); err != nil {
		return nil, err
	}
	return claim, nil
}
