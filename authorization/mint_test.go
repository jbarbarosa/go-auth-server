package authorization

import (
	"crypto/ed25519"
	"testing"
)

func TestCanMintJWTFromCredentials(t *testing.T) {
	type scenario struct {
		name   string
		claims Claims
	}

	for _, scenario := range []scenario{
		{
			name: "simple credentials",
			claims: Claims{
				Email: "foo",
			},
		},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			_, privkey, err := ed25519.GenerateKey(nil)

			if err != nil {
				t.Fatalf("test %s: could not generate key pairs, error: %s", scenario.name, err)
			}

			_, err = NewMinter(privkey).Mint(scenario.claims)

			if err != nil {
				t.Fatalf("test %s: expected no errors, got %s", scenario.name, err)
			}
		})
	}
}
