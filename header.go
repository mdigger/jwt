package jwt

import (
	"encoding/base64"
	"encoding/json"
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
