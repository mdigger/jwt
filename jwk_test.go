package jwt_test

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/mdigger/jwt"
)

func TestJWK(t *testing.T) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	JSONOut := enc.Encode

	for _, key := range []interface{}{
		jwt.NewES256Key(),
		&(jwt.NewES256Key().PublicKey),
		jwt.NewRS256Key(),
		&(jwt.NewRS256Key().PublicKey),
	} {
		fmt.Printf("%T:\n", key)
		data, err := jwt.JWKEncode(key, "test")
		if err != nil {
			t.Fatal(err)
		}
		if err = JSONOut(data); err != nil {
			t.Fatal(err)
		}
		key2, err := data.Decode()
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("Restored: %T\n", key2)
		if key3, ok := key2.(*rsa.PrivateKey); ok {
			if err := key3.Validate(); err != nil {
				t.Error("validate rsa.PrivateKey error:", err)
			}
		}
		fmt.Println(strings.Repeat("-", 80))
	}
}
