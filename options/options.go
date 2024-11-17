package options

import (
	"github.com/Ashik80/oauth2jwtgen/claims"
	"github.com/Ashik80/oauth2jwtgen/store"
	"github.com/golang-jwt/jwt"
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

func (s *AuthOptions) AddIdTokenClaims(c *claims.JWTIdClaims) {
	s.idTokenClaims = new(claims.JWTIdClaims)
	s.idTokenClaims.Name = c.Name
	s.idTokenClaims.GivenName = c.GivenName
	s.idTokenClaims.FamilyName = c.FamilyName
	s.idTokenClaims.Email = c.Email
	s.idTokenClaims.Picture = c.Picture
	s.idTokenClaims.Locale = c.Locale
	s.idTokenClaims.PreferredUsername = c.PreferredUsername
	s.idTokenClaims.StandardClaims = jwt.StandardClaims{}
}

func (s *AuthOptions) IsIdTokenClaimsSet() bool {
	return s.idTokenClaims != nil
}

func (s *AuthOptions) GetIdToken() *claims.JWTIdClaims {
	return s.idTokenClaims
}
