package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
)

// Encode возвращает подписанный с помощью ключа key токен из claimset.
// Если ключ не указан, то токен не будет подписан. Key может быть представлен
// в виде строки или ключа для RSA или ECDSA. А может быть представлен в виде
// функции, которая возвращает нужный ключ. Поддерживаются следующие форматы
// ключа:
//
// 	*rsa.PrivateKey
// 	*ecdsa.PrivateKey
// 	string
// 	[]byte
// 	fmt.Stringer
//
// Так же поддерживаются следующие форматы функции для передачи ключа:
// 	func() interface{}
// 	func() string, interface{}
//
// В последних случаях, кроме ключа так же возвращается его идентификатор.
func Encode(claimset, key interface{}) (string, error) {
	// кодируем данные токена в формат JSON
	data, err := json.Marshal(claimset)
	if err != nil {
		return "", err
	}
	// если для получения ключа задана функция, то вызываем ее
	var keyID string // идентификатор ключа
	switch fkey := key.(type) {
	case func() interface{}:
		key = fkey()
	case func() (string, interface{}):
		keyID, key = fkey()
	}
	alg, hash := algorithm(key) // название алгоритма для подписи
	if hash != 0 && !hash.Available() {
		return "", ErrBadHashFunc
	}
	// взводим флаг, что требуется подпись токена
	var signFlag = (key != nil && !strings.EqualFold(alg, "none"))
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
	var token bytes.Buffer
	var enc = base64.NewEncoder(base64.RawURLEncoding, &token)
	_, _ = enc.Write(header)
	_ = enc.Close()
	_ = token.WriteByte('.')
	enc = base64.NewEncoder(base64.RawURLEncoding, &token)
	_, _ = enc.Write(data)
	_ = enc.Close()
	// если указан ключ, то подписываем токен
	if signFlag {
		siganture, err := sign(token.Bytes(), key)
		if err != nil {
			return "", err
		}
		// добавляем сигнатуру
		_ = token.WriteByte('.')
		enc = base64.NewEncoder(base64.RawURLEncoding, &token)
		_, _ = enc.Write(siganture)
		_ = enc.Close()
	} else {
		_ = token.WriteByte('.') // в любом случае добпвляем разделитель в конце
	}
	return token.String(), nil
}
