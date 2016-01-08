package jwt_test

import (
	"fmt"
	"time"

	"github.com/mdigger/jwt"
)

func Example() {
	// создаем шаблон и описываем в нем те вещи, которые
	// мы хотели бы включать во все токены
	tmpl := &jwt.Template{
		Issuer:  "me.mdigger.test",
		Expire:  time.Hour,
		Created: true,
		Signer:  jwt.NewSignerHS256([]byte(`top secret`)),
	}
	// описываем дополнительные поля токена (можно структурой)
	data := map[string]interface{}{
		"user-id": "34529345",
	}
	// создаем и подписываем токен
	token, err := tmpl.Token(data)
	if err != nil {
		fmt.Println("Error creating:", err)
		return
	}
	// разбираем токен и получаем данные
	// если токен не валиден, то вернется ошибка
	if err := tmpl.Parse(token, &data); err != nil {
		fmt.Println("Error parsing:", err)
		return
	}
}
