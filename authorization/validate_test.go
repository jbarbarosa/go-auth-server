package authorization_test

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jbarbarosa/go-auth-server/authorization"
)

func fatal(t *testing.T, err error) {
	if err != nil {
		t.Fatalf(err.Error())
	}
}

func mintFactory(t *testing.T) (*authorization.JWTMinter, ed25519.PublicKey) {
	pubkey, privkey, err := ed25519.GenerateKey(nil)
	fatal(t, err)

	return &authorization.JWTMinter{Privkey: privkey}, pubkey
}

func TestValidateJWTString(t *testing.T) {
	type scenario struct {
		name   string
		token  string
		pubkey ed25519.PublicKey
		err    error
	}

	minter, pubkey := mintFactory(t)
	_, wrongpubkey := mintFactory(t)
	token, err := minter.Mint(*authorization.NewClaims("test@test.com"))

	fatal(t, err)
	
  for _, scenario := range []scenario{
		{
			name:   "Simple token",
			token:  token,
			pubkey: pubkey,
		},
		{
			name:   "Broken token",
			token:  "I'm Borked",
			pubkey: pubkey,
			err:    jwt.ErrTokenMalformed,
		},
		{
			name:   "Pubkey mismatch",
			token:  token,
			pubkey: wrongpubkey,
			err:    jwt.ErrEd25519Verification,
		},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			token, err := authorization.NewValidator(scenario.pubkey).Validate(scenario.token)

			if err != nil {
				if scenario.err == nil {
					t.Fatalf("test %s: expected no error, got the following error: %s", scenario.name, err)
				} else if !errors.Is(err, scenario.err) {
					t.Fatalf("test %s: expected the following error: %s, got %s", scenario.name, scenario.err, err)
				}
				return
			}

			j, err := json.Marshal(token.Claims)

			fatal(t, err) 

			var claims authorization.Claims
			err = json.Unmarshal(j, &claims)

			fatal(t, err)
		})
	}
}
