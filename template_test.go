package jwt

import (
	"fmt"
	"testing"
	"time"
)

var key = []byte(`TOPSECRET`)

func TestTemplate1(t *testing.T) {
	tmpl := &Template{
		Issuer:    "issuer",
		Subject:   "subject",
		Audience:  []string{"audience 1", "audience 2"},
		NotBefore: time.Minute * -30,
	}
	test := map[string]interface{}{
		"data": 1,
	}
	token, err := tmpl.Token(test)
	if err.Error() != "empty signer" {
		t.Error("empty signer")
	}
	err = tmpl.Parse(token, nil)
	if err.Error() != "empty signer" {
		t.Error("empty signer")
	}
	tmpl.Signer = NewSignerHS256(key)
	token, err = tmpl.Token(test)
	if err != nil {
		t.Error("bad token")
	}
	err = tmpl.Parse(token, &test)
	if err != nil {
		t.Error(err)
	}
	// fmt.Println(test)
	err = tmpl.Parse(token, nil)
	if err != nil {
		t.Error(err)
	}
	token, err = tmpl.Token(nil)
	if err != nil {
		t.Error("bad nil token")
	}
	test2 := map[string]string{
		"data": "1",
	}
	token, err = tmpl.Token(test2)
	if err != nil {
		t.Error("empty string data")
	}
	_ = token
	err = tmpl.Parse([]byte(`aaa.bbb.ccc`), nil)
	if err == nil {
		t.Error("bad token")
	}
}

func TestMap(t *testing.T) {
	// fmt.Println("key:", base64.RawURLEncoding.EncodeToString(key))
	var tmpl = &Template{
		Issuer:   "i am",
		Audience: []string{"test audience"},
		Expire:   time.Hour,
		Created:  true,
		Signer:   NewSignerHS256(key),
	}
	test := &struct {
		GroupId     string `json:"gid"`
		UserId      string
		EmptyValue  string
		EmptyValue2 string    `json:",omitempty"`
		EmptyValue3 string    `,omitempty`
		IgnoreValue string    `json:"-"`
		BaseValue   string    `base`
		Time        time.Time `json:",omitempty"`
		Time2       time.Time `json:"ddd,"`
		Bool        bool      `-`
		private     bool
	}{
		GroupId: "group",
		UserId:  "user-id",
	}
	token, err := tmpl.Token(test)
	if err != nil {
		t.Fatal(err)
	}

	err = tmpl.Parse(token, test)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(test)
}
