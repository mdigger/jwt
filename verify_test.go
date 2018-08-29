package jwt

import (
	"testing"
	"time"
)

func TestVerify(t *testing.T) {
	payload := JSON{
		"iss":      "http://service.example.com/",
		"sub":      "2934852845",
		"iat":      Time{Time: time.Now()},
		"exp":      Time{Time: time.Now().Add(time.Hour)},
		"name":     "Dmitry Sedykh",
		"email":    "dmitrys@example.com",
		"birthday": Time{Time: time.Date(1971, time.December, 24, 0, 0, 0, 0, time.Local)},
		"nonce":    Nonce(8)(),
	}
	token, err := Encode(payload, "my secret sign key")
	if err != nil {
		t.Fatal(err)
	}
	// println("token:", token)

	getKey := func(string) interface{} {
		return "my secret sign key"
	}
	if _, err := Verify(token, getKey); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyNotSignedToken(t *testing.T) {
	var conf = &Config{
		Issuer:   "http://service.example.com/",
		UniqueID: Nonce(8),
	}
	token, err := conf.Token(JSON{"sub": "9394203942934"})
	if err != nil {
		t.Fatal(err)
	}
	// fmt.Println(token)
	if _, err := Verify(token, ""); err.Error() != "token not signed" {
		t.Fatal("bad verify unsigned token")
	}

}
