package jwt

import (
	"crypto/rand"
	"encoding/base64"
	"io"
)

// Nonce возвращает функцию, которая генерирует случайные псевдо-уникальные
// строки заданного размера. Можно использовать ее для создания уникальных
// значений поля nonce токенов.
func Nonce(length uint8) func() string {
	// вычисляем размер необходимого бинарного буфера для генерации случайной
	// строки указанного размера
	var dataLength = base64.RawURLEncoding.DecodedLen(int(length))
	// возвращаем анонимную функцию, которая будет создавать строки в кодировке
	// base64 со случайными данными
	return func() string {
		var data = make([]byte, dataLength)
		io.ReadFull(rand.Reader, data)
		return base64.RawURLEncoding.EncodeToString(data)
	}
}
