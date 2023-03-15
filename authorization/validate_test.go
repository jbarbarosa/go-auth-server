package authorization

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"log"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func testMintFactory() (*JWTMinter, ed25519.PublicKey) {
	pubkey, privkey, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatalf("Unable to generate keys, error: %s", err)
	}
	return &JWTMinter{privkey: privkey}, pubkey
}

func TestValidateJWTString(t *testing.T) {
	type testcase struct {
		name   string
		token  string
		pubkey ed25519.PublicKey
		err    error
	}

	minter, pubkey := testMintFactory()

	token, err := minter.Mint(*NewClaims("test@test.com"))

	if err != nil {
		log.Fatalf("Unable to generate test tokens, error: %s", err)
	}

	cases := []testcase{
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
	}

	for _, kase := range cases {
		t.Run(kase.name, func(t *testing.T) {
			token, err := NewValidator(kase.pubkey).Validate(kase.token)

			if err != nil {
				if kase.err == nil {
					t.Fatalf("test %s: expected no error, got the following error: %s", kase.name, err)
				} else if !errors.Is(err, kase.err) {
					t.Fatalf("test %s: expected the following error: %s, got %s", kase.name, kase.err, err)
				}
				return
			}

			j, err := json.Marshal(token.Claims)

			if err != nil {
				t.Fatalf("test %s: unable to marshal token, err: %s", kase.name, err)
			}

			var claims Claims
			err = json.Unmarshal(j, &claims)

			if err != nil {
				t.Fatalf("test %s: unable to convert token claims into struct, err: %s", kase.name, err)
			}
		})
	}
}
