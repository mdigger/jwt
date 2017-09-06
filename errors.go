package jwt

import "errors"

// Ошибки создания и верификации токенов.
var (
	ErrEmptySignKey    = errors.New("empty token sign key")
	ErrInvalid         = errors.New("invalid token")
	ErrBadType         = errors.New("bad token type")
	ErrNotSigned       = errors.New("token not signed")
	ErrCreatedAfterNow = errors.New("token created after now")
	ErrNotBeforeNow    = errors.New("token not before now")
	ErrExpired         = errors.New("token expired")
	ErrBadHashFunc     = errors.New("hash function for key is not availible")
)
