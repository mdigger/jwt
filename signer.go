package jwt

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"hash"
)

// Signer describes information for token-signing.
type Signer struct {
	hash hash.Hash // the generation algorithm of the signature
	name string    // the name of the algorithm
}

// NewSigner returns an initialized token-based algorithm is SHA256 algorithm.
func NewSignerHS256(key []byte) *Signer {
	return &Signer{
		hash: hmac.New(sha256.New, key),
		name: "HS256",
	}
}

// NewSignerHS384 returns an initialized token-based algorithm is SHA384.
func NewSignerHS384(key []byte) *Signer {
	return &Signer{
		hash: hmac.New(sha512.New384, key),
		name: "HS384",
	}
}

// NewSignerHS512 returns an initialized token-based algorithm is SHA512.
func NewSignerHS512(key []byte) *Signer {
	return &Signer{
		hash: hmac.New(sha512.New, key),
		name: "HS512",
	}
}

// Sign returns the signed token.
func (s Signer) Sign(token []byte) []byte {
	// encode to a string and combine it with a header
	data := make([]byte, base64.RawURLEncoding.EncodedLen(len(token)))
	base64.RawURLEncoding.Encode(data, token)
	data = append(append(getHeader(s.name), '.'), data...)
	s.hash.Reset()
	s.hash.Write(data)
	sign := make([]byte, base64.RawURLEncoding.EncodedLen(s.hash.Size()))
	base64.RawURLEncoding.Encode(sign, s.hash.Sum(nil))
	return append(append(data, '.'), sign...)
}

// Parse parses a token and returns its contents.
func (s Signer) Parse(token []byte) ([]byte, error) {
	// разделяем токен на составные части
	parts := bytes.SplitN(token, []byte{'.'}, 3)
	if len(parts) != 3 {
		return nil, errors.New("bad token parts")
	}
	// decode the header
	data := make([]byte, base64.RawURLEncoding.DecodedLen(len(parts[0])))
	n, err := base64.RawURLEncoding.Decode(data, parts[0])
	if err != nil {
		return nil, err
	}
	header, err := parseHeader(data[:n]) // parse the header token
	if err != nil {
		return nil, err
	}
	if header.Typ != "" && header.Typ != tokenName {
		return nil, errors.New("bad token type")
	}
	if header.Alg != s.name {
		return nil, errors.New("bad token sign algorithm")
	}
	// decode the signature
	data = make([]byte, s.hash.Size())
	if _, err := base64.RawURLEncoding.Decode(data, parts[2]); err != nil {
		return nil, err
	}
	s.hash.Reset()
	// consider the checksum of the token, including header and content
	if _, err := s.hash.Write(token[:len(parts[0])+len(parts[1])+1]); err != nil {
		return nil, err
	}
	if !hmac.Equal(s.hash.Sum(nil), data) { // compare signature
		return nil, errors.New("bad token sign")
	}
	// decode and return the contents of the token
	data = make([]byte, base64.RawURLEncoding.DecodedLen(len(parts[1])))
	n, err = base64.RawURLEncoding.Decode(data, parts[1])
	if err != nil {
		return nil, err
	}
	return data[:n], nil
}
