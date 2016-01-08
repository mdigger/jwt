package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"
	"unicode"
)

// Template описывает основные поля токена, которые будут заполнены автоматически.
type Template struct {
	Issuer    string        // кто выдал
	Subject   string        // тема
	Audience  []string      // кому предназначен
	Created   bool          // добавлять дату и время создания
	Expire    time.Duration // время жизни
	NotBefore time.Duration // добавлять время начала использования
	Signer    *Signer       // генератор подписи
}

// Token возвращает подписанный токен, сгенерированный на основании данных из шаблона и данных
// пользователя. Подпись осуществляется методом, указанным в шаблоне.
func (t *Template) Token(obj interface{}) (token []byte, err error) {
	if t.Signer == nil {
		return nil, errors.New("empty signer")
	}
	dict := make(map[string]interface{})
	// добавляем поля из шаблона
	if t.Issuer != "" {
		dict["iss"] = t.Issuer
	}
	if t.Subject != "" {
		dict["sub"] = t.Subject
	}
	if len(t.Audience) > 0 {
		if len(t.Audience) == 1 {
			dict["aud"] = t.Audience[0]
		} else {
			dict["aud"] = t.Audience
		}
	}
	now := time.Now().UTC()
	if t.Expire > 0 {
		dict["exp"] = now.Add(t.Expire).Unix()
	}
	if t.NotBefore != 0 {
		dict["nbf"] = now.Add(t.NotBefore).Unix()
	}
	if t.Created {
		dict["iat"] = now.Unix()
	}
	// добавляем пользовательские данные, если формат поддерживается
	switch obj := obj.(type) {
	case map[string]string: // словарь строк (на всякий случай)
		for key, value := range obj {
			dict[key] = value
		}
	case map[string]interface{}: // словарь объектов
		for key, value := range obj {
			dict[key] = value
		}
	case nil:
		break
	default: // возможно, что структура (поддерживаем только их)
		v := reflect.ValueOf(obj)
		if v.Kind() == reflect.Ptr { // если это указатель, то переключаемся на сам элемент
			v = v.Elem()
		}
		if v.Kind() == reflect.Invalid { // если пустая не инициализированная структура
			break
		}
		if v.Kind() != reflect.Struct { // это не структура
			return nil, fmt.Errorf("unsupported type %T", obj)
		}
		typ := v.Type()                     // получаем информацию о типе структуры
		for i := 0; i < v.NumField(); i++ { // перебираем все поля
			field := typ.Field(i)
			if field.PkgPath != "" {
				continue // приватное поле
			}
			tag := field.Tag.Get("json") // получаем таг для JSON
			// если таг для JSON не определен, а определено глобальное имя, то используем его
			if tag == "" && strings.Index(string(field.Tag), ":") < 0 {
				tag = string(field.Tag)
			}
			if tag == "-" { // указано игнорировать
				continue
			}
			value := v.Field(i) // получаем значение
			// проверяем, что у тега есть параметры
			if indx := strings.IndexRune(tag, ','); indx >= 0 {
				// игнорируем пустые значения если указано
				if strings.Contains(tag[indx+1:], "omitempty") {
					zero := reflect.Zero(value.Type()).Interface()
					if reflect.DeepEqual(value.Interface(), zero) {
						continue
					}
				}
				tag = tag[:indx] // название будет первым полем
			}
			// если имя не задано через тег, то используем имя поля
			if tag == "" {
				runes := []rune(field.Name)
				runes[0] = unicode.ToLower(runes[0]) // первая буква маленькая
				tag = string(runes)
			}
			dict[tag] = value.Interface() // сохраняем значение
		}
	}
	// декодируем в JSON
	data, err := json.Marshal(dict)
	if err != nil {
		return nil, err
	}
	// получили полностью сформированный словарь токена — подписываем его.
	return t.Signer.Sign(data), nil
}

// Parse разбирает токен и десериализует его содержимое в указанный объект.
func (t *Template) Parse(token []byte, obj interface{}) error {
	if t.Signer == nil {
		return errors.New("empty signer")
	}
	data, err := t.Signer.Parse(token) // разбираем токен и проверяем валидность подписи
	if err != nil {
		return err
	}
	// для начала проверяем все стандартные поля из шаблона
	var verify struct {
		Issuer    string `json:"iss"`
		Subject   string `json:"sub"`
		Created   int64  `json:"iat"`
		Expire    int64  `json:"exp"`
		NotBefore int64  `json:"nbf"`
	}
	if err := json.Unmarshal(data, &verify); err != nil {
		return err
	}
	if t.Issuer != "" && t.Issuer != verify.Issuer {
		return errors.New("bad issuer")
	}
	if t.Subject != "" && t.Subject != verify.Subject {
		return errors.New("bad subject")
	}
	if t.Created && verify.Created == 0 {
		return errors.New("created not set")
	}
	if t.Expire != 0 && verify.Expire == 0 {
		return errors.New("expire not set")
	}
	if t.NotBefore != 0 && verify.NotBefore == 0 {
		return errors.New("notBefore not set")
	}
	now := time.Now().UTC()
	if verify.Expire > 0 && time.Unix(verify.Expire, 0).Before(now) {
		return errors.New("token expired")
	}
	if verify.Created > 0 && time.Unix(verify.Created, 0).After(now) {
		return errors.New("bad create date & time")
	}
	if verify.NotBefore > 0 && time.Unix(verify.NotBefore, 0).After(now) {
		return errors.New("using before set time")
	}

	if obj != nil { // десериализуем данные пользователя в указанный им объект
		return json.Unmarshal(data, obj)
	}
	return nil
}
