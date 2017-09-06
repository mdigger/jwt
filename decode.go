package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// Decode декодирует содержимое токена в claimset. По ходу распаковки проверяются
// основные временные поля токена.
func Decode(token string, claimset interface{}) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ErrInvalid
	}
	// разбираем основной раздел токена
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}
	var times = new(struct {
		Created   Time `json:"iat"`
		Expires   Time `json:"exp"`
		NotBefore Time `json:"nbf"`
	})
	if err := json.Unmarshal(data, times); err != nil {
		return err
	}
	// проверяем поля со временем
	now := time.Now() // текущее время
	if !times.Created.IsZero() && times.Created.After(now) {
		return ErrCreatedAfterNow
	}
	if !times.Expires.IsZero() && times.Expires.Before(now) {
		return ErrExpired
	}
	if !times.NotBefore.IsZero() && times.NotBefore.After(now) {
		return ErrNotBeforeNow
	}
	// декодируем данные в пользовательский объект, если он определен
	if claimset != nil {
		if err := json.Unmarshal(data, claimset); err != nil {
			return err
		}
	}

	return nil
}
