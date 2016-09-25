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

// Template describes the basic fields of token that will be filled in
// automatically.
type Template struct {
	Issuer    string
	Subject   string
	Audience  []string
	Created   bool
	Expire    time.Duration
	NotBefore time.Duration
	Signer    *Signer
}

// Token returns the signed token generated based on the data from a template
// and user data. The signature is made by the method specified in the template.
func (t *Template) Token(obj interface{}) (token []byte, err error) {
	if t.Signer == nil {
		return nil, errors.New("empty signer")
	}
	dict := make(map[string]interface{})
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
	switch obj := obj.(type) {
	case map[string]string:
		for key, value := range obj {
			dict[key] = value
		}
	case map[string]interface{}:
		for key, value := range obj {
			dict[key] = value
		}
	case nil:
		break
	default:
		v := reflect.ValueOf(obj)
		if v.Kind() == reflect.Ptr {
			v = v.Elem()
		}
		if v.Kind() == reflect.Invalid {
			break
		}
		if v.Kind() != reflect.Struct {
			return nil, fmt.Errorf("unsupported type %T", obj)
		}
		typ := v.Type()
		for i := 0; i < v.NumField(); i++ {
			field := typ.Field(i)
			if field.PkgPath != "" {
				continue // private field
			}
			tag := field.Tag.Get("json")
			if tag == "" && strings.Index(string(field.Tag), ":") < 0 {
				tag = string(field.Tag)
			}
			if tag == "-" {
				continue
			}
			value := v.Field(i)
			if indx := strings.IndexRune(tag, ','); indx >= 0 {
				if strings.Contains(tag[indx+1:], "omitempty") {
					zero := reflect.Zero(value.Type()).Interface()
					if reflect.DeepEqual(value.Interface(), zero) {
						continue
					}
				}
				tag = tag[:indx]
			}
			if tag == "" {
				runes := []rune(field.Name)
				runes[0] = unicode.ToLower(runes[0])
				tag = string(runes)
			}
			dict[tag] = value.Interface()
		}
	}
	data, err := json.Marshal(dict)
	if err != nil {
		return nil, err
	}
	return t.Signer.Sign(data), nil
}

// Parse parses a token and deserializes its contents to the specified object.
func (t *Template) Parse(token []byte, obj interface{}) error {
	if t.Signer == nil {
		return errors.New("empty signer")
	}
	data, err := t.Signer.Parse(token)
	if err != nil {
		return err
	}
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

	if obj != nil {
		return json.Unmarshal(data, obj)
	}
	return nil
}
