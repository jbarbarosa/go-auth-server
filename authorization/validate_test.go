package authorization

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"log"
	"testing"
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

	jwt, pubkey := testMintFactory()

	token, err := jwt.Mint(*NewClaims("test@test.com"))

	if err != nil {
		log.Fatalf("Unable to generate test tokens, error: %s", err)
	}

	cases := []testcase{
		{
			name:   "Simple payload",
			token:  token,
			pubkey: pubkey,
		},
	}

	for _, kase := range cases {
		t.Run(kase.name, func(t *testing.T) {
			token, err := NewValidator(kase.pubkey).Validate(kase.token)

			if err != nil {
				if kase.err != nil {
					t.Fatalf("test %s: expected the following error: %s, got no error", kase.name, kase.err)
				} else {
					if !errors.Is(kase.err, err) {
						t.Fatalf("test %s: expected the following error: %s, got error: %s", kase.name, kase.err, err)
					}
				}
			}

			j, _ := json.Marshal(token.Claims)
			var claims Claims
			err = json.Unmarshal(j, &claims)

			if err != nil {
				t.Fatalf("test %s: unable to convert token claims into struct, err: %s", kase.name, err)
			}
		})
	}
}
