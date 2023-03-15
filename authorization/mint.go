package authorization

import (
	jwt "github.com/golang-jwt/jwt/v5"
)

type JWTMinter struct {
	privkey interface{}
}

func NewMinter(key interface{}) *JWTMinter {
	return &JWTMinter{key}
}

func (m JWTMinter) Mint(claims Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	signed, err := token.SignedString(m.privkey)

	if err != nil {
		return "", err
	}

	return signed, nil
}
