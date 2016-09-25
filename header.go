package jwt

import (
	"encoding/base64"
	"encoding/json"
)

const tokenName = "JWT"

// header describes the header token with information about the signature.
type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// getHeader returns the generated header token specifying the algorithm for
// signing.
func getHeader(alg string) []byte {
	data, _ := json.Marshal(header{
		Alg: alg,
		Typ: tokenName,
	})
	result := make([]byte, base64.RawURLEncoding.EncodedLen(len(data)))
	base64.RawURLEncoding.Encode(result, data)
	return result
}

// parseHeader parses the header of the token.
func parseHeader(data []byte) (h *header, err error) {
	h = new(header)
	err = json.Unmarshal(data, h)
	return
}
