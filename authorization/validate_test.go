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

func TestShouldValidateSimpleToken(t *testing.T) {
	type scenario struct {
		name   string
		token  string
		pubkey ed25519.PublicKey
		err    error
	}

	minter, pubkey := mintFactory(t)
	token, err := minter.Mint(*authorization.ClaimsForUser(authorization.User{"test@test.com", make([]string, 0)}))

	fatal(t, err)

	for _, scenario := range []struct {
		name   string
		token  string
		pubkey ed25519.PublicKey
		err    error
	}{
		{
			name:   "Simple token",
			token:  token,
			pubkey: pubkey,
		},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			token, err := authorization.NewValidator(scenario.pubkey).Validate(scenario.token)

			if err != nil {
				t.Fatalf("test %s: expected no error, got the following error: %s", scenario.name, err)
			}

			j, err := json.Marshal(token.Claims)

			fatal(t, err)

			var claims authorization.Claims
			err = json.Unmarshal(j, &claims)

			fatal(t, err)
		})
	}
}

func TestShouldReturnJWTStringErrors(t *testing.T) {
	minter, pubkey := mintFactory(t)
	_, wrongpubkey := mintFactory(t)
	token, err := minter.Mint(*authorization.ClaimsForUser(authorization.User{"test@test.com", make([]string, 0)}))

	fatal(t, err)

	for _, scenario := range []struct {
		name   string
		token  string
		pubkey ed25519.PublicKey
		err    error
	}{
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
			_, err := authorization.NewValidator(scenario.pubkey).Validate(scenario.token)

			if err == nil {
				t.Fatalf("scenario expected error, got no errors")
			}

			if !errors.Is(err, scenario.err) {
				t.Fatalf("scenario expected the following error: %s, got %s", scenario.err, err)
			}
		})
	}
}
