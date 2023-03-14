package authorization

import (
	jwt "github.com/golang-jwt/jwt/v5"
)

type JWT struct {
	key interface{}
}

func NewMinter(key interface{}) *JWT {
	return &JWT{key}
}

func (m JWT) Mint(claims Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	signed, err := token.SignedString(m.key)

	if err != nil {
		return "", err
	}

	return signed, nil
}
