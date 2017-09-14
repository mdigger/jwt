package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
)

var (
	// RSAKeyBits содержит длину ключа для генерации RSA. Используется в
	// функции NewRS256Key.
	RSAKeyBits = 2048
	// ECDSACurve содержит инициализированный elliptic.Curve для генерации
	// ECDSA ключа. Используется в функции NewES256Key.
	ECDSACurve = elliptic.P256()
)

// NewHS256Key возвращает новый ключ для подписи в формате HS256 указанной
// длины.
//
// Вызывает panic в случае ошибки создания.
func NewHS256Key(length int) []byte {
	var data = make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		panic(err)
	}
	return data
}

// NewRS256Key возвращает новый ключ для подписи в формате RS256.
// Длина ключа задается переменной RSAKeyBits.
//
// Вызывает panic в случае ошибки создания.
func NewRS256Key() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, RSAKeyBits)
	if err != nil {
		panic(err)
	}
	return key
}

// NewES256Key возвращает новый ключ для подписи в формате ESxxx. По умолчанию
// возвращается ES256 ключ, но это можно изменить через переменную ECDSACurve.
//
// Вызывает panic в случае ошибки создания.
func NewES256Key() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(ECDSACurve, rand.Reader)
	if err != nil {
		panic(err)
	}
	return key
}

// JWK описывает формат данных ключа.
//
// The "use" and "key_ops" JWK members SHOULD NOT be used together.
// Mimetype: application/jwk+json (application/jwk-set+json)
type JWK struct {
	// The "kty" (key type) parameter identifies the cryptographic algorithm
	// family used with the key, such as "RSA" or "EC".
	Type string `json:"kty"`
	// The "use" (public key use) parameter identifies the intended use of
	// the public key.  The "use" parameter is employed to indicate whether
	// a public key is used for encrypting data or verifying the signature
	// on data.
	//
	// Values defined by this specification are:
	// 	- "sig" (signature)
	// 	- "enc" (encryption)
	Usage string `json:"use,omitempty"`
	// The "key_ops" (key operations) parameter identifies the operation(s)
	// for which the key is intended to be used.  The "key_ops" parameter is
	// intended for use cases in which public, private, or symmetric keys
	// may be present.
	//
	// Its value is an array of key operation values.  Values defined by
	// this specification are:
	// 	- "sign" (compute digital signature or MAC)
	// 	- "verify" (verify digital signature or MAC)
	// 	- "encrypt" (encrypt content)
	// 	- "decrypt" (decrypt content and validate decryption, if applicable)
	// 	- "wrapKey" (encrypt key)
	// 	- "unwrapKey" (decrypt key and validate decryption, if applicable)
	// 	- "deriveKey" (derive key)
	// 	- "deriveBits" (derive bits not to be used as a key)
	KeyOps []string `json:"key_ops,omitempty"`
	// The "alg" (algorithm) parameter identifies the algorithm intended for
	// use with the key.
	Algorithm string `json:"alg"`
	// The "kid" (key ID) parameter is used to match a specific key.  This
	// is used, for instance, to choose among a set of keys within a JWK Set
	// during key rollover.
	ID string `json:"kid,omitempty"`
	// ECDSA Public
	Curve string `json:"crv,omitempty"` // Curve
	X     string `json:"x,omitempty"`   // X Coordinate
	Y     string `json:"y,omitempty"`   // Y Coordinate
	// RSA Public
	N string `json:"n,omitempty"` // Modulus
	E string `json:"e,omitempty"` // Exponent
	// Private RSA & ECDSA
	D string `json:"d,omitempty"` // ECC Private Key or RSA Private Exponent
	// RSA Private
	P   string   `json:"p,omitempty"`   // First Prime Factor
	Q   string   `json:"q,omitempty"`   // Second Prime Factor
	DP  string   `json:"dp,omitempty"`  // First Factor CRT Exponent
	DQ  string   `json:"dq,omitempty"`  // Second Factor CRT Exponent
	QI  string   `json:"qi,omitempty"`  // First CRT Coefficient
	OTH []rsaCtr `json:"oth,omitempty"` // Other Primes Info
	// HS
	K string `json:"k,omitempty"`
}

type rsaCtr struct {
	R string `json:"r"`
	D string `json:"d"`
	T string `json:"t"`
}

// JWKEncode возвращает представление ключа в формате JWK.
// 	https://tools.ietf.org/html/rfc7517
func JWKEncode(key interface{}, keyID string) (jwk *JWK, err error) {
	jwk = &JWK{
		ID:    keyID,
		Usage: "sig",
	}
	switch key := key.(type) {
	case *rsa.PublicKey:
		jwk.Type = "RSA"
		jwk.Algorithm = "RS256"
		jwk.E = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
		jwk.N = base64.RawURLEncoding.EncodeToString(key.N.Bytes())

	case *rsa.PrivateKey:
		jwk, err = JWKEncode(key.Public(), keyID)
		if err != nil {
			return nil, err
		}
		jwk.D = base64.RawURLEncoding.EncodeToString(key.D.Bytes())
		jwk.P = base64.RawURLEncoding.EncodeToString(key.Primes[0].Bytes())
		jwk.Q = base64.RawURLEncoding.EncodeToString(key.Primes[1].Bytes())
		jwk.DP = base64.RawURLEncoding.EncodeToString(key.Precomputed.Dp.Bytes())
		jwk.DQ = base64.RawURLEncoding.EncodeToString(key.Precomputed.Dq.Bytes())
		jwk.QI = base64.RawURLEncoding.EncodeToString(key.Precomputed.Qinv.Bytes())
		for _, crt := range key.Precomputed.CRTValues {
			jwk.OTH = append(jwk.OTH, rsaCtr{
				R: base64.RawURLEncoding.EncodeToString(crt.R.Bytes()),
				D: base64.RawURLEncoding.EncodeToString(crt.Exp.Bytes()),
				T: base64.RawURLEncoding.EncodeToString(crt.Coeff.Bytes()),
			})
		}

	case *ecdsa.PublicKey:
		p := key.Curve.Params()
		n := p.BitSize / 8
		if p.BitSize%8 != 0 {
			n++
		}
		x := key.X.Bytes()
		if n > len(x) {
			x = append(make([]byte, n-len(x)), x...)
		}
		y := key.Y.Bytes()
		if n > len(y) {
			y = append(make([]byte, n-len(y)), y...)
		}
		jwk.Type = "EC"
		jwk.Algorithm = "ES" + key.Params().Name[2:]
		jwk.Curve = p.Name
		jwk.X = base64.RawURLEncoding.EncodeToString(x)
		jwk.Y = base64.RawURLEncoding.EncodeToString(y)

	case *ecdsa.PrivateKey:
		jwk, err = JWKEncode(key.Public(), keyID)
		if err != nil {
			return nil, err
		}
		n := key.Curve.Params().BitSize / 8
		d := key.D.Bytes()
		if n > len(d) {
			d = append(make([]byte, n-len(d)), d...)
		}
		jwk.D = base64.RawURLEncoding.EncodeToString(d)

	case []byte:
		jwk.Type = "oct"
		jwk.Algorithm = "HS256"
		jwk.K = base64.RawURLEncoding.EncodeToString(key)
	case string:
		jwk.Type = "oct"
		jwk.Algorithm = "HS256"
		jwk.K = base64.RawURLEncoding.EncodeToString([]byte(key))
	case fmt.Stringer:
		jwk.Type = "oct"
		jwk.Algorithm = "HS256"
		jwk.K = base64.RawURLEncoding.EncodeToString([]byte(key.String()))
	default:
		return nil, fmt.Errorf("unsupported key type %T", key)
	}
	return
}

// Decode декодирует описание в ключ.
func (key *JWK) Decode() (interface{}, error) {
	if key.Type == "RSA" ||
		(key.N != "" && key.E != "" &&
			(key.Algorithm == "" || key.Algorithm == "RS256")) {
		e, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil {
			return nil, err
		}
		n, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			return nil, err
		}
		rsaKey := &rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Int64()),
		}
		// проверяем, что это не публичный ключ
		if key.D != "" {
			d, err := base64.RawURLEncoding.DecodeString(key.D)
			if err != nil {
				return nil, err
			}
			rsaPrivateKey := &rsa.PrivateKey{
				PublicKey: *rsaKey,
				D:         new(big.Int).SetBytes(d),
			}
			if key.P != "" && key.Q != "" {
				p, err := base64.RawURLEncoding.DecodeString(key.P)
				if err != nil {
					return nil, err
				}
				q, err := base64.RawURLEncoding.DecodeString(key.Q)
				if err != nil {
					return nil, err
				}
				rsaPrivateKey.Primes = []*big.Int{
					new(big.Int).SetBytes(p),
					new(big.Int).SetBytes(q),
				}
			}
			if key.DP != "" {
				dp, err := base64.RawURLEncoding.DecodeString(key.DP)
				if err != nil {
					return nil, err
				}
				rsaPrivateKey.Precomputed.Dp = new(big.Int).SetBytes(dp)
			}
			if key.DQ != "" {
				dq, err := base64.RawURLEncoding.DecodeString(key.DQ)
				if err != nil {
					return nil, err
				}
				rsaPrivateKey.Precomputed.Dq = new(big.Int).SetBytes(dq)
			}
			if key.QI != "" {
				qi, err := base64.RawURLEncoding.DecodeString(key.QI)
				if err != nil {
					return nil, err
				}
				rsaPrivateKey.Precomputed.Qinv = new(big.Int).SetBytes(qi)
			}
			if len(key.OTH) > 0 {
				rsaPrivateKey.Precomputed.CRTValues = make([]rsa.CRTValue, len(key.OTH))
				for i, crt := range key.OTH {
					r, err := base64.RawURLEncoding.DecodeString(crt.R)
					if err != nil {
						return nil, err
					}
					d, err := base64.RawURLEncoding.DecodeString(crt.D)
					if err != nil {
						return nil, err
					}
					t, err := base64.RawURLEncoding.DecodeString(crt.T)
					if err != nil {
						return nil, err
					}
					rsaPrivateKey.Precomputed.CRTValues[i] = rsa.CRTValue{
						R:     new(big.Int).SetBytes(r),
						Exp:   new(big.Int).SetBytes(d),
						Coeff: new(big.Int).SetBytes(t),
					}
				}
			}
			return rsaPrivateKey, nil
		}
		return rsaKey, nil
	} else if key.Type == "EC" ||
		(key.Curve != "" && key.X != "" && key.Y != "") {
		x, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil {
			return nil, err
		}
		y, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			return nil, err
		}
		var crv elliptic.Curve
		switch key.Curve {
		case "P-256":
			crv = elliptic.P256()
		case "P-384":
			crv = elliptic.P384()
		case "P-521":
			crv = elliptic.P521()
		}
		ecdsaKey := &ecdsa.PublicKey{
			Curve: crv,
			X:     (&big.Int{}).SetBytes(x),
			Y:     (&big.Int{}).SetBytes(y),
		}
		// проверяем, что это не публичный ключ
		if key.D != "" {
			d, err := base64.RawURLEncoding.DecodeString(key.D)
			if err != nil {
				return nil, err
			}
			return &ecdsa.PrivateKey{
				PublicKey: *ecdsaKey,
				D:         (&big.Int{}).SetBytes(d),
			}, nil
		}
		return ecdsaKey, nil
	} else {
		// unsupported key type
		return nil, fmt.Errorf("unsupported key type: %T", key)
	}
}
