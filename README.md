# JSON Web Token

[![GoDoc](https://godoc.org/github.com/mdigger/jwt?status.svg)](https://godoc.org/github.com/mdigger/jwt)
[![Build Status](https://travis-ci.org/mdigger/jwt.svg?branch=master)](https://travis-ci.org/mdigger/jwt)
[![Coverage Status](https://coveralls.io/repos/github/mdigger/jwt/badge.svg?branch=master)](https://coveralls.io/github/mdigger/jwt?branch=master)

```go
package mail

import (
	"fmt"
	"time"

	"github.com/mdigger/jwt"
)

func main() {
	// create a pattern and describe in it the things that we would like to
	// include all the tokens
	conf := &jwt.Config{
		Issuer:  "me.mdigger.test",
		Expire:  time.Hour,
		Created: true,
		Key:     `top secret`,
	}
	// describe additional fields of token (structure)
	data := jwt.JSON{
		"user-id": "34529345",
	}
	// create and sign the token
	token, err := conf.Token(data)
	if err != nil {
		log.Fatalln("Error creating:", err)
	}
	// parse a token and get data
	// if the token is not valid, then return an error
	if err := jwt.Decode(token, &data); err != nil {
		log.Fatalln("Error parsing:", err)
	}
}
```