package jwt

import (
	"encoding/json"
)

// Decode декодирует содержимое токена в claimset. По ходу распаковки проверяются
// основные временные поля токена, но не подпись токена.
func Decode(token string, claimset interface{}) error {
	claim, err := Verify(token, nil)
	if err != nil {
		return err
	}

	if claimset == nil {
		return nil
	}

	// декодируем данные в пользовательский объект, если он определен
	return json.Unmarshal(claim, claimset)
}
