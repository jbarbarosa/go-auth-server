package authorization

import (
	"crypto/ed25519"
	"testing"
)

func TestCanMintJWTFromUser(t *testing.T) {
	type scenario struct {
		name   string
    user User
	}

	for _, scenario := range []scenario{
		{
			name: "simple credentials",
			user: User{
				Email: "foo",
			},
		},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			_, privkey, err := ed25519.GenerateKey(nil)

			if err != nil {
				t.Fatalf("test %s: could not generate key pairs, error: %s", scenario.name, err)
			}

      claims := ClaimsForUser(scenario.user)
			_, err = NewMinter(privkey).Mint(*claims)

			if err != nil {
				t.Fatalf("test %s: expected no errors, got %s", scenario.name, err)
			}
		})
	}
}
