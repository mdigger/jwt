package jwt

import (
	"fmt"
	"reflect"
	"strings"
	"time"
	"unicode"
)

// JSON является синонимом для быстрого создания map в формате JSON.
type JSON = map[string]interface{}

// Config описывает шаблон для генерации токена. Поля, указанные в нем,
// будут автоматически добавляться при генерации токена. Любые общие
// дополнительные поля для токена можно указать в Private. Если задана функция
// Nonce, то в каждый токен будет добавляться уникальная строка, возвращаемая
// этой функцией.
//
// Для автоматической подписи токена необходимо указать ключ. В зависимости от
// его типа будут использоваться разные алгоритмы для генерации подписи.
// Для *rsa.PrivateKey будет создаваться токен с алгоритмом подписи RS256.
// Для *ecdsa.PrivateKey - ES256, ES384 или ES512, в зависимости от параметров
// созданного ключа. Для string, []byte или любого другого объекта, который
// поддерживает строковое представление (fmt.Stringer) - HS256.
//
// Чтобы указать в заголовке токена идентификатор ключа, используемого для
// подписи, нужно задать значение KeyID.
type Config struct {
	Issuer    string        // iss - идентификатор выпускающего
	Created   bool          // iat - добавлять время создания
	Expires   time.Duration // exp - добавлять время жизни
	NotBefore time.Duration // nbf - добавлять время начала действия
	Type      string        // typ - тип токена
	UniqueID  func() string // nonce - генератор случайной строки
	Private   JSON          // дополнительные именованные поля

	Key interface{} // ключ для подписи токена или функция его возвращающая
}

// Token возвращает сгенерированный токен на основании шаблона и
// предоставленных данных. В качестве payload можно указать
// map[string]interface{} или собственный объект.
//
// Есть несколько отличий от стандартной сериализации в формат JSON, которые
// заложены в этой функции. Во-первых, все поля, представленные в виде
// time.Time кодируются в числовом виде, а не строками, как это стандартно
// происходит в Go. А не заданные значение time.Time автоматически игнорируются.
// Во-вторых, в структурах для именования полей могут использоваться теги "json"
// и "jwt". Последний имеет чуть больший приоритет, поэтому вы можете специально
// для токенов указывать другие имена. Если имя поля не определено в теге, то
// используется само имя поля, но первая его буква при этом становится строчной,
// что больше соответствует формату JSON токена.
func (c *Config) Token(claimset interface{}) (string, error) {
	// формируем содержимое токена
	result := make(JSON)
	// добавляем дополнительные поля из шаблона
	for key, value := range c.Private {
		if vt, ok := value.(time.Time); ok {
			if vt.IsZero() {
				continue // игнорируем пустые даты
			}
			value = vt.Unix() // преобразуем в числовой вид
		}
		result[key] = value
	}
	// генерируем поля на основе данных шаблона
	if c.Issuer != "" {
		result["iss"] = c.Issuer
	}
	// добавляем данные с временем
	now := time.Now()
	if c.Created {
		result["iat"] = now.Add(-10 * time.Second).Unix()
	}
	if c.Expires > 0 {
		result["exp"] = now.Add(c.Expires).Unix()
	}
	if c.NotBefore != 0 {
		result["nbf"] = now.Add(c.NotBefore).Unix()
	}
	if c.Type != "" {
		result["typ"] = c.Type
	}
	if c.UniqueID != nil {
		result["jti"] = c.UniqueID()
	}
	// добавляем данные из объекта
	switch claimset := claimset.(type) {
	case map[string]string: // только строковые значения
		for key, value := range claimset {
			result[key] = value
		}
	case JSON: // словарь в формате JSON
		for key, value := range claimset {
			if vt, ok := value.(time.Time); ok {
				if vt.IsZero() {
					continue // игнорируем пустые даты
				}
				value = vt.Unix() // преобразуем в числовой вид
			}
			result[key] = value
		}
	default: // поддержка структур
		v := reflect.ValueOf(claimset)
		if v.Kind() == reflect.Ptr {
			v = v.Elem()
		}
		// проверяем, что данный тип данных мы поддерживаем
		if k := v.Kind(); k == reflect.Invalid || k != reflect.Struct {
			return "", fmt.Errorf("unsupported claimset type %T", claimset)
		}
		typ := v.Type()
		// перебираем все поля структуры
		for i := 0; i < v.NumField(); i++ {
			field := typ.Field(i)
			if field.PkgPath != "" {
				continue // игнорируем приватные поля
			}
			// подбираем имя элемента токена
			tag := field.Tag.Get("jwt")
			if tag == "" {
				tag = field.Tag.Get("json")
			}
			if tag == "" && strings.Index(string(field.Tag), ":") < 0 {
				tag = string(field.Tag)
			}
			if tag == "-" {
				continue // явно указано игнорирование
			}
			value := v.Field(i)
			// пропускаем пустые значения, которые указано игнорировать
			if indx := strings.IndexRune(tag, ','); indx >= 0 {
				if strings.Contains(tag[indx+1:], "omitempty") {
					zero := reflect.Zero(value.Type()).Interface()
					if reflect.DeepEqual(value.Interface(), zero) {
						continue
					}
				}
				tag = tag[:indx]
			}
			// если имя не определено в теге элемента, то берем имя поля
			if tag == "" {
				// первую букву в имени приводим к нижнему регистру
				runes := []rune(field.Name)
				runes[0] = unicode.ToLower(runes[0])
				tag = string(runes)
			}
			val := value.Interface()
			// подмена данных для времени
			if vt, ok := val.(time.Time); ok {
				if vt.IsZero() {
					continue // игнорируем пустые даты
				}
				val = vt.Unix() // подменяем на число
			}
			// добавляем значение поля в наш результирующий словарь
			result[tag] = val
		}
	}
	// кодируем и возвращаем токен
	return Encode(result, c.Key)
}
