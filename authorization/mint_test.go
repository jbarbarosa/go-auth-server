package authorization

import (
	"crypto/ed25519"
	"testing"
)

func TestCanMintJWTFromCredentials(t *testing.T) {
	type testcase struct {
		name   string
		claims Claims
	}

	cases := []testcase{
		{
			name: "simple credentials",
			claims: Claims{
				Email: "foo",
			},
		},
	}

	for _, v := range cases {
		t.Run(v.name, func(t *testing.T) {
			_, privkey, err := ed25519.GenerateKey(nil)

			if err != nil {
				t.Fatalf("test %s: could not generate key pairs, error: %s", v.name, err)
			}

			_, err = NewMinter(privkey).Mint(v.claims)

			if err != nil {
				t.Fatalf("test %s: expected no errors, got %s", v.name, err)
			}
		})
	}
}
