package options

import (
	"github.com/Ashik80/oauth2jwtgen/claims"
	"github.com/Ashik80/oauth2jwtgen/store"
	"github.com/golang-jwt/jwt"
)

type AuthOptions struct {
	Validity             *Validity
	Store                store.TokenStore
	idTokenClaims        *claims.JWTIdClaims
	RefreshInCookie      bool
	AccessInCookie       bool
	RefreshCookieOptions *CookieOptions
	AccessCookieOptions  *CookieOptions
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

func (s *AuthOptions) GetIdTokenClaims() *claims.JWTIdClaims {
	return s.idTokenClaims
}

func (s *AuthOptions) SetRefreshTokenInCookie(cookieOptions *CookieOptions) {
	s.RefreshInCookie = true
	s.RefreshCookieOptions = new(CookieOptions)
	s.RefreshCookieOptions.SetName("refresh_token")
	s.RefreshCookieOptions.MapFrom(cookieOptions)
	if s.RefreshCookieOptions.MaxAge == 0 {
		s.RefreshCookieOptions.MaxAge = s.Validity.RefreshExpiresIn
	}
}

func (s *AuthOptions) SetAccessTokenInCookie(cookieOptions *CookieOptions) {
	s.AccessInCookie = true
	s.AccessCookieOptions = new(CookieOptions)
	s.AccessCookieOptions.SetName("access_token")
	s.AccessCookieOptions.MapFrom(cookieOptions)
	if s.AccessCookieOptions.MaxAge == 0 {
		s.AccessCookieOptions.MaxAge = int(s.Validity.AccessExpiresIn)
	}
}
