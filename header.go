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
func getHeader(alg string) []byte {
	data, _ := json.Marshal(header{
		Alg: alg,
		Typ: tokenName,
	})
	result := make([]byte, base64.RawURLEncoding.EncodedLen(len(data)))
	base64.RawURLEncoding.Encode(result, data)
	return result
}

func parseHeader(data []byte) (h *header, err error) {
	h = new(header)
	err = json.Unmarshal(data, h)
	return
}
