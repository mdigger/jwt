# JSON Web Token

[![Go Reference](https://pkg.go.dev/badge/github.com/mdigger/jwt.svg)](https://pkg.go.dev/github.com/mdigger/jwt)

```golang
import "github.com/mdigger/jwt"

// create a pattern and describe in it the things that we would like to
// include all the tokens
conf := &jwt.Config{
	Issuer:  "me.mdigger.test",
	Expires:  time.Hour,
	Created: true,
	Key:     `top secret`,
}
// describe additional fields of token (structure)
data := jwt.JSON{
	"sub": "34529345",
	"email": "dmitrys@example.com",
	"name": "Dmitry Sedykh",
	"birthday": jwt.Time{time.Date(1971, time.December, 24, 0, 0, 0, 0, time.Local)},
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
```