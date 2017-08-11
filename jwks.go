package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
)

// Keys описывает список публичных ключей в формате JWKS в разобранном виде.
// Список упорядочен по идентификаторам и содержит только публичные ключи.
// Поддерживаются форматы RSA и ECDSA.
type Keys struct {
	list map[string]crypto.PublicKey
}

// LoadKeys загружает и возвращает список ключей. Для загрузки используется
// http.DefaultClient клиент.
func LoadKeys(url string) (*Keys, error) {
	resp, err := http.DefaultClient.Get(url)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, errors.New(resp.Status)
	}
	var keys = new(Keys)
	err = json.NewDecoder(resp.Body).Decode(&keys)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	return keys, nil
}

// Add добавляет новый ключ в список.
func (k *Keys) Add(keyID string, key crypto.PublicKey) {
	if k.list == nil {
		k.list = make(map[string]crypto.PublicKey)
	}
	k.list[keyID] = key
}

// Get возвращает ключ с указанным идентификатором. Если ключа с таким
// идентификатором нет или он поддерживает другой алгоритм, то возвращается nil.
// Название алгоритма можно не указывать, тогда оно не используется для проверки.
func (k Keys) Get(alg, keyID string) crypto.PublicKey {
	key := k.list[keyID]
	if alg != "" {
		if name, _ := algorithm(key); name != alg {
			return nil
		}
	}
	return key
}

// UnmarshalJSON создает и инициализирует список ключей из JWKS формата.
// Поддерживаются только RSA и EC ключи, у которых задано имя. Все остальные -
// игнорируются.
func (ks *Keys) UnmarshalJSON(data []byte) error {
	list := new(struct {
		Keys []*keyItem `json:"keys"`
	})
	if err := json.Unmarshal(data, list); err != nil {
		return err
	}
	keys := make(map[string]crypto.PublicKey, len(list.Keys))
	for _, key := range list.Keys {
		if key.ID == "" {
			continue // игнорируем ключи без идентификатора
		}
		if key.Type == "RSA" ||
			(key.N != "" && key.E != "" &&
				(key.Algorithm == "" || key.Algorithm == "RS256")) {
			e, err := base64.RawURLEncoding.DecodeString(key.E)
			if err != nil {
				return err
			}
			n, err := base64.RawURLEncoding.DecodeString(key.N)
			if err != nil {
				return err
			}
			rsaKey := &rsa.PublicKey{
				N: new(big.Int).SetBytes(n),
				E: int(new(big.Int).SetBytes(e).Int64()),
			}
			keys[key.ID] = rsaKey
		} else if key.Type == "EC" ||
			(key.Curve != "" && key.X != "" && key.Y != "") {
			x, err := base64.RawURLEncoding.DecodeString(key.E)
			if err != nil {
				return err
			}
			y, err := base64.RawURLEncoding.DecodeString(key.N)
			if err != nil {
				return err
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
			keys[key.ID] = ecdsaKey
		} else {
			// unsupported key type
		}
	}
	ks.list = keys
	return nil
}

// MarshalJSON отдает список ключей в формате JWKS.
func (ks Keys) MarshalJSON() ([]byte, error) {
	var keys = make([]*keyItem, 0, len(ks.list))
	for id, key := range ks.list {
		item, err := jwkEncode(key, id)
		if err != nil {
			return nil, err
		}
		keys = append(keys, item)
	}
	return json.Marshal(struct {
		Keys []*keyItem `json:"keys"`
	}{keys})
}

// keyItem описывает формат данных ключа в JWK.
type keyItem struct {
	Type      string `json:"kty"`
	Algorithm string `json:"alg"`
	Usage     string `json:"use"`
	ID        string `json:"kid"`
	// RSA
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
	// ECDSA
	Curve string `json:"crv,omitempty"`
	X     string `json:"x,omitempty"`
	Y     string `json:"y,omitempty"`
}
