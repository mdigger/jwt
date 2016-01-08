package jwt

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/kr/pretty"
)

var key = []byte(`TOPSECRET`)

func TestSign(t *testing.T) {
	s := NewSignerHS256(key)
	s.hash.Reset()
	s.hash.Write([]byte("test"))
	sum := s.hash.Sum(nil)
	if hex.EncodeToString(sum) != `a3174174280008f8fcf2aa9aef674e26c8d66e2746ada2b8428279c090594fd9` {
		t.Error("bad sign")
	}
}

func TestMap(t *testing.T) {
	fmt.Println("key:", base64.RawURLEncoding.EncodeToString(key))
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
	pretty.Println(test)
}
