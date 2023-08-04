package authorization

import (
	"crypto/ed25519"

	"github.com/golang-jwt/jwt/v5"
)

type JWTValidator struct {
	pubkey ed25519.PublicKey
}

func NewValidator(pubkey ed25519.PublicKey) *JWTValidator {
	return &JWTValidator{pubkey}
}

func (v JWTValidator) Validate(token string) (*jwt.Token, error) {
	t, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		return v.pubkey, nil
	})

	return t, err
}
