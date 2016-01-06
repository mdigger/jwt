package token

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/kr/pretty"
)

func TestSign(t *testing.T) {
	key := make([]byte, 1<<8)
	if _, err := rand.Read(key); err != nil {
		t.Error(err)
	}
	s := NewSignerHS256(key)
	for i := 0; i < 10; i++ {
		s.hash.Reset()
		s.hash.Write([]byte("test"))
		sum := s.hash.Sum(nil)
		fmt.Println(hex.EncodeToString(sum), len(sum))
	}
}

func TestMap(t *testing.T) {
	key := make([]byte, 1<<8)
	if _, err := rand.Read(key); err != nil {
		t.Error(err)
	}
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
