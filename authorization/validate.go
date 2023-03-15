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

	if t.Valid {
		return t, nil
	} else if errors.Is(err, jwt.ErrTokenMalformed) {
		return nil, fmt.Errorf("Malformed Token")
	} else if errors.Is(err, jwt.ErrTokenExpired) {
		return nil, fmt.Errorf("Token expired")
	} else if errors.Is(err, jwt.ErrTokenNotValidYet) {
		return nil, fmt.Errorf("Token is not yet valid")
	}
	return nil, fmt.Errorf("Unknown error: %s", err)
}
