package authorization

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

type JWTValidator struct {
	pubkey ed25519.PublicKey
}

func NewValidator(pubkey ed25519.PublicKey) *JWTValidator {
	return &JWTValidator{pubkey}
}

func (v JWTValidator) Validate(token string) (*jwt.Token, error) {
	t, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		return v.pubkey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenMalformed) {
			return nil, jwt.ErrTokenMalformed
		} else if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, jwt.ErrTokenExpired
		} else if errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, jwt.ErrTokenNotValidYet
		}
		return nil, fmt.Errorf("Unknown error: %s", err)
	}

	return t, nil
}
