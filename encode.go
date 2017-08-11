package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Encode возвращает подписанный с помощью ключа key токен из claimset.
// Если ключ не указан, то токен не будет подписан. В параметре keyID можно
// указать идентификатор ключа, который будет добавлен в заголовок токена.
func Encode(claimset, key interface{}, keyID string) (string, error) {
	// кодируем данные токена в формат JSON
	data, err := json.Marshal(claimset)
	if err != nil {
		return "", err
	}

	alg, hash := algorithm(key) // название алгоритма для подписи
	if hash != 0 && !hash.Available() {
		return "", errors.New("hash function for key is not availible")
	}
	// взводим флаг, что требуется подпись токена
	signFlag := (key != nil && !strings.EqualFold(alg, "none"))
	if !signFlag {
		keyID = "" // если подпись не требуется, то и ключ всегда будет пустой
	}

	// формируем заголовок токена
	header, err := json.Marshal(&struct {
		Algorithm string `json:"alg"`           // алгоритм подписи
		Type      string `json:"typ"`           // тип токена
		KeyID     string `json:"kid,omitempty"` // необязательный идентификатор ключа
	}{
		Algorithm: alg,
		Type:      "JWT",
		KeyID:     keyID,
	})
	if err != nil {
		return "", err
	}
	// формируем токен
	token := fmt.Sprintf("%s.%s",
		base64.RawURLEncoding.EncodeToString(header),
		base64.RawURLEncoding.EncodeToString(data))
	// если указан ключ, то подписываем токен
	if signFlag {
		siganture, err := sign([]byte(token), key)
		if err != nil {
			return "", err
		}
		// добавляем сигнатуру
		token = fmt.Sprintf("%s.%s", token,
			base64.RawURLEncoding.EncodeToString(siganture))
	} else {
		token = token + "." // добавляем пустую сигнатуру
	}
	return token, nil
}
