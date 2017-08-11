package jwt

import (
	"testing"
)

func TestSign(t *testing.T) {
	rsaKey := NewRS256Key()
	if name, _ := algorithm(rsaKey); name != "RS256" {
		t.Error("bad RSA algorithm name")
	}
	ecdsaKey := NewES256Key()
	if name, _ := algorithm(ecdsaKey); name != "ES256" {
		t.Error("bad ECDSA algorithm name")
	}
	hmacKey := "HS256 secret key"
	if name, _ := algorithm(hmacKey); name != "HS256" {
		t.Error("bad HMAC algorithm name")
	}
	if name, _ := algorithm(nil); name != "none" {
		t.Error("bad NONE algorithm name")
	}

	var data = []byte("test body")

	if signature, err := sign(data, hmacKey); err != nil {
		t.Fatal(err)
	} else if err := verify(data, signature, hmacKey); err != nil {
		t.Fatal(err)
	}

	if signature, err := sign(data, rsaKey); err != nil {
		t.Fatal(err)
	} else if err := verify(data, signature, rsaKey); err != nil {
		t.Fatal(err)
	}

	if signature, err := sign(data, ecdsaKey); err != nil {
		t.Fatal(err)
	} else if err := verify(data, signature, ecdsaKey); err != nil {
		t.Fatal(err)
	}

}
