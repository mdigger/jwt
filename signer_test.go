package jwt

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestSign(t *testing.T) {
	s := NewSignerHS256(key)
	s.hash.Reset()
	s.hash.Write([]byte("test"))
	sum := s.hash.Sum(nil)
	if hex.EncodeToString(sum) != `a3174174280008f8fcf2aa9aef674e26c8d66e2746ada2b8428279c090594fd9` {
		t.Error("bad sign")
	}
}

func TestSigner(t *testing.T) {
	signer := NewSignerHS256([]byte(`top secret`))
	_, err := signer.Parse([]byte(`aaa.bbb`))
	if err.Error() != "bad token parts" {
		t.Error("bad token parts")
	}
	_, err = signer.Parse([]byte(`aaa.bbb.ccc`))
	if err == nil {
		t.Error("bad token encoder")
	}
	h, _ := json.Marshal(header{
		Alg: "HS256",
		Typ: "JJJ",
	})
	hh := base64.RawURLEncoding.EncodeToString(h)
	_, err = signer.Parse([]byte(hh + `1.bbb.ccc`))
	if err == nil {
		t.Error("bad token header")
	}
	_, err = signer.Parse([]byte(hh + `.bbb.ccc`))
	if err.Error() != "bad token type" {
		t.Error("bad token type")
	}
	_, err = signer.Parse(append(getHeader("none"), []byte(`.bbb.ccc`)...))
	if err.Error() != "bad token sign algorithm" {
		t.Error("bad token sign algorithm")
	}
	_, err = signer.Parse(append(getHeader(signer.name), []byte(`.bbb.ccc`)...))
	if err.Error() != "bad token sign" {
		t.Error("bad token sign")
	}
	_, err = signer.Parse(append(getHeader(signer.name), []byte(`.bbb.+++`)...))
	if err == nil {
		t.Error("bad token sign data")
	}
	_, err = signer.Parse([]byte(
		`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LisrKw.o3jUAiMkhChgQsKbFbcQySzNjfEoSjp9hIJalHnEVYQ`))
	if err != nil {
		t.Error("bad token?")
	}
}

func TestSigner2(t *testing.T) {
	if NewSignerHS384([]byte(`top secret`)) == nil {
		t.Error("NewSignerHS384 error")
	}
	if NewSignerHS512([]byte(`top secret`)) == nil {
		t.Error("NewSignerHS512 error")
	}
}
