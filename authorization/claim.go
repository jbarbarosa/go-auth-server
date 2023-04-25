package authorization

import (
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Claims struct {
	Email string `json:"email"`
  Permissions []string `json:"permissions"`
	jwt.RegisteredClaims
}

func ClaimsForUser(user User) *Claims {
	newuuid, err := uuid.NewRandom()

	if err != nil {
		log.Fatalf("FATAL: unable to generate uuids:\n%v", err)
	}

	return &Claims{
		user.Email,
    user.Permissions,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			Issuer:    "GoAuthServer",
			Subject:   "EndUser",
			ID:        newuuid.String(),
		},
	}
}
