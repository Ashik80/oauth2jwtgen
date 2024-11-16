package accessor

import (
	"time"

	"github.com/golang-jwt/jwt"
)

type JWTAccessClaims struct {
	jwt.StandardClaims
	Scope string `json:"scope,omitempty"`
}

func GenerateClaims(a JWTAccess, sub string, issuer string, aud string, scope string) *JWTAccessClaims {
	iat := time.Now().UTC().Unix()

	claims := &JWTAccessClaims{
		StandardClaims: jwt.StandardClaims{
			Issuer:    issuer,
			Audience:  aud,
			Subject:   sub,
			IssuedAt:  iat,
			ExpiresAt: iat + a.GetAccessExpiresIn(),
		},
		Scope: scope,
	}
	return claims
}
