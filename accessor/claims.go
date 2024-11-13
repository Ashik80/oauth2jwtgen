package accessor

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt"
)

type JWTAccessClaims struct {
	jwt.StandardClaims
}

func (c *JWTAccessClaims) Valid() error {
	if time.Unix(c.ExpiresAt, 0).Before(time.Now()) {
		return errors.New("invalid access token")
	}
	return nil
}

func GenerateDefaultClaims(a JWTAccess, sub string) *JWTAccessClaims {
	iat := time.Now().UTC().Unix()

	host := "http://localhost:8080"

	claims := &JWTAccessClaims{
		StandardClaims: jwt.StandardClaims{
			Issuer:    host,
			Audience:  host,
			Subject:   sub,
			IssuedAt:  iat,
			ExpiresAt: iat + a.GetExpiresIn(),
		},
	}
	return claims
}
