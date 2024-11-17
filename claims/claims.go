package claims

import (
	"time"

	"github.com/golang-jwt/jwt"
)

type JWTClaims struct {
	AccessClaims *JWTAccessClaims
	IdClaims     *JWTIdClaims
}

type JWTAccessClaims struct {
	jwt.StandardClaims
	Scope string `json:"scope,omitempty"`
}

type JWTIdClaims struct {
	jwt.StandardClaims
	Name              string `json:"name,omitempty"`
	GivenName         string `json:"given_name,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	Email             string `json:"email,omitempty"`
	Picture           string `json:"picture,omitempty"`
	Locale            string `json:"locale,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
}

func GenerateClaims(sub string, issuer string, aud string, scope string, expiresAfterSeconds int64) *JWTAccessClaims {
	iat := time.Now().UTC().Unix()

	claims := &JWTAccessClaims{
		StandardClaims: jwt.StandardClaims{
			Issuer:    issuer,
			Audience:  aud,
			Subject:   sub,
			IssuedAt:  iat,
			ExpiresAt: iat + expiresAfterSeconds,
		},
		Scope: scope,
	}
	return claims
}

func CopyStandardClaims(dest *jwt.StandardClaims, src *jwt.StandardClaims) {
	dest.Issuer = src.Issuer
	dest.Audience = src.Audience
	dest.Subject = src.Subject
	dest.IssuedAt = src.IssuedAt
	dest.ExpiresAt = src.ExpiresAt
}
