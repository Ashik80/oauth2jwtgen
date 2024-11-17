package options

import (
	"github.com/Ashik80/oauth2jwtgen/claims"
	"github.com/Ashik80/oauth2jwtgen/store"
)

type AuthOptions struct {
	Validity      *Validity
	Store         store.TokenStore
	idTokenClaims *claims.JWTIdClaims
}

func DefaultAuthOptions() *AuthOptions {
	v := new(Validity)
	v.SetDefaultAccessExpiresIn()
	v.SetDefaultRefreshExpiresIn()

	return &AuthOptions{
		Validity: v,
	}
}

func (s *AuthOptions) AddIdTokenClaims(claims *claims.JWTIdClaims) {
	s.idTokenClaims = claims
}
