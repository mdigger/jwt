package jwt_test

import (
	"fmt"
	"log"
	"time"

	"github.com/mdigger/jwt"
)

var token string

func init() {
	claimset := jwt.JSON{
		"iss":      "http://service.example.com/",
		"sub":      "2934852845",
		"iat":      jwt.Time{time.Now()},
		"exp":      jwt.Time{time.Now().Add(time.Hour)},
		"name":     "Dmitry Sedykh",
		"email":    "dmitrys@example.com",
		"birthday": jwt.Time{time.Date(1971, time.December, 24, 8, 43, 0, 0, time.Local)},
		"nonce":    jwt.Nonce(8)(),
	}
	var err error
	token, err = jwt.Encode(claimset, "my secret sign key", "")
	if err != nil {
		panic(err)
	}
}

func ExampleEncode() {
	// описываем данные токена (не обязательно в JSON)
	claimset := jwt.JSON{
		"iss":      "http://service.example.com/",
		"sub":      "2934852845",
		"iat":      jwt.Time{time.Now()},
		"exp":      jwt.Time{time.Now().Add(time.Hour)},
		"name":     "Dmitry Sedykh",
		"email":    "dmitrys@example.com",
		"birthday": jwt.Time{time.Date(1971, time.December, 24, 0, 0, 0, 0, time.Local)},
		"nonce":    jwt.Nonce(8)(),
	}
	// создаем токен с подписью HS256 с секретным ключем
	token, err := jwt.Encode(claimset, "my secret sign key", "")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("token:", token)
}

func ExampleDecode() {
	// описываем структуру с данными, которые хотим распаковать из токена
	var claimset = new(struct {
		Issuer   string   `json:"iss"`
		Subject  string   `json:"sub"`
		Created  jwt.Time `json:"iat"`
		Expired  jwt.Time `json:"exp"`
		Name     string
		Email    string
		Birthday jwt.Time // время представлено числовом виде
		Nonce    string
	})
	// извлекаем данные из токена
	if err := jwt.Decode(token, claimset); err != nil {
		log.Fatal(err)
	}
	fmt.Println(claimset)
}

func ExampleVerify() {
	// проверка подписи токена с простым ключем
	if err := jwt.Verify(token, "my secret sign key"); err != nil {
		log.Fatal(err)
	}

	// описываем функцию, которая будет возвращать наш ключ в зависимости от
	// алгоритма и идентификатора ключа
	getMyKey := func(keyID, alg string) []byte {
		if alg != "HS256" || keyID != "" {
			return nil
		}
		return []byte("my secret sign key")
	}
	// вызываем проверку подписи с вызовом функции получения ключа
	if err := jwt.Verify(token, getMyKey); err != nil {
		log.Fatal(err)
	}
}

func ExampleNonce() {
	var conf = &jwt.Config{
		Issuer: "http://service.example.com/",
		Nonce:  jwt.Nonce(8), // задаем функцию генерации случайного nonce
	}
	token, err := conf.Token(jwt.JSON{"sub": "9394203942934"})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("token:", token)
}

func ExampleJSON() {
	// определяем содержимое токена
	claimset := jwt.JSON{
		"iss":      "http://service.example.com/",
		"sub":      "2934852845",
		"iat":      jwt.Time{time.Now()},
		"exp":      jwt.Time{time.Now().Add(time.Hour)},
		"name":     "Dmitry Sedykh",
		"email":    "dmitrys@example.com",
		"birthday": jwt.Time{time.Date(1971, time.December, 24, 0, 0, 0, 0, time.Local)},
		"nonce":    jwt.Nonce(8)(),
	}
	// создаем токен без подписи
	token, err := jwt.Encode(claimset, nil, "")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("token:", token)
}

func ExampleConfig() {
	// инициализируем шаблон с описанием основных полей токена
	var conf = &jwt.Config{
		Issuer:  "http://test.example.com/auth",
		Created: true,                   // добавлять дату создания
		Expires: time.Hour,              // время жизни
		Nonce:   jwt.Nonce(8),           // добавлять nonce
		Private: jwt.JSON{"temp": true}, // дополнительные поля
		Key:     jwt.NewRS256Key(),      // ключ для подписи
	}
	// создаем токен с указанными полями
	token, err := conf.Token(jwt.JSON{
		"sub":      "938102384109384",
		"email":    "user@example.com",
		"name":     "Test User",
		"birthday": time.Date(1971, time.December, 24, 0, 0, 0, 0, time.Local),
		"temp":     false, // переопределяем поля в шаблоне
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("token:", token)
}

func ExampleTime() {
	// описываем структуру с данными, которые хотим распаковать из токена
	var claimset = new(struct {
		Issuer   string   `json:"iss"`
		Subject  string   `json:"sub"`
		Created  jwt.Time `json:"iat"`
		Expired  jwt.Time `json:"exp"`
		Name     string
		Email    string
		Birthday jwt.Time // время представлено числовом виде
		Nonce    string
	})
	// извлекаем данные из токена
	if err := jwt.Decode(token, claimset); err != nil {
		log.Fatal(err)
	}
	fmt.Println(claimset.Birthday.UTC())
	// Output: 1971-12-24 05:43:00 +0000 UTC
}

func ExampleKeys() {
	keys, err := jwt.LoadKeys("https://www.googleapis.com/oauth2/v3/certs")
	if err != nil {
		log.Fatal(err)
	}
	if err = jwt.Verify(token, keys.Get); err != nil {
		log.Fatal(err)
	}
}
