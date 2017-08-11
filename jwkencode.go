package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
)

// jwkEncode возвращает публичную часть RSA или ECDSA в формате JWK.
// 	https://tools.ietf.org/html/rfc7517
//
// На самом деле я немного схалтурил, чтобы облегчить себе жизнь: в качестве
// ключа можно указать не только публичный, но и приватный. В последнем случае
// просто автоматически возьмется его публичная часть.
func jwkEncode(key crypto.PublicKey, keyID string) (*keyItem, error) {
	var result = &keyItem{
		ID:    keyID,
		Usage: "sig",
	}
repeat:
	switch pub := key.(type) {
	case *rsa.PublicKey:
		result.Type = "RSA"
		result.Algorithm = "RS256"
		result.E = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
		result.N = base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
		return result, nil
	case rsa.PublicKey:
		key = &pub
		goto repeat
	case *rsa.PrivateKey:
		key = &pub.PublicKey
		goto repeat

	case *ecdsa.PublicKey:
		p := pub.Curve.Params()
		n := p.BitSize / 8
		if p.BitSize%8 != 0 {
			n++
		}
		x := pub.X.Bytes()
		if n > len(x) {
			x = append(make([]byte, n-len(x)), x...)
		}
		y := pub.Y.Bytes()
		if n > len(y) {
			y = append(make([]byte, n-len(y)), y...)
		}
		result.Type = "EC"
		result.Algorithm = "ES" + pub.Params().Name[2:]
		result.Curve = p.Name
		result.X = base64.RawURLEncoding.EncodeToString(x)
		result.Y = base64.RawURLEncoding.EncodeToString(y)
		return result, nil
	case *ecdsa.PrivateKey:
		key = &pub.PublicKey
		goto repeat
	case ecdsa.PublicKey:
		key = &pub
		goto repeat

	default:
		return nil, fmt.Errorf("unsupported key type %T", key)
	}
}
