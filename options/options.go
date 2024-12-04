package options

import (
	"sync"

	"github.com/Ashik80/oauth2jwtgen/claims"
	"github.com/Ashik80/oauth2jwtgen/store"
	"github.com/golang-jwt/jwt"
)

type AuthOptions struct {
	Validity             *Validity
	Store                store.TokenStore
	RefreshInCookie      bool
	AccessInCookie       bool
	RefreshCookieOptions *CookieOptions
	AccessCookieOptions  *CookieOptions
	idTokenClaims        map[string]*claims.JWTIdClaims
	accessTokenClaims    map[string]*claims.JWTAccessClaims
	mu                   sync.Mutex
}

func DefaultAuthOptions() *AuthOptions {
	v := new(Validity)
	v.SetDefaultAccessExpiresIn()
	v.SetDefaultRefreshExpiresIn()

	return &AuthOptions{
		Validity: v,
	}
}

func (s *AuthOptions) SetIdTokenClaims(username string, c *claims.JWTIdClaims) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.idTokenClaims == nil {
		s.idTokenClaims = make(map[string]*claims.JWTIdClaims)
	}
	s.idTokenClaims[username] = c
	s.idTokenClaims[username].StandardClaims = jwt.StandardClaims{}
}

func (s *AuthOptions) IsIdTokenClaimsSet(username string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.idTokenClaims == nil {
		return false
	}
	_, exists := s.idTokenClaims[username]
	return exists
}

func (s *AuthOptions) GetIdTokenClaims(username string) *claims.JWTIdClaims {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.idTokenClaims[username]
}

func (s *AuthOptions) SetRefreshTokenInCookie(cookieOptions *CookieOptions) {
	s.RefreshInCookie = true
	s.RefreshCookieOptions = new(CookieOptions)
	s.RefreshCookieOptions = cookieOptions
	s.RefreshCookieOptions.SetName("refresh_token")
	if s.RefreshCookieOptions.MaxAge == 0 {
		s.RefreshCookieOptions.MaxAge = s.Validity.RefreshExpiresIn
	}
}

func (s *AuthOptions) SetAccessTokenInCookie(cookieOptions *CookieOptions) {
	s.AccessInCookie = true
	s.AccessCookieOptions = new(CookieOptions)
	s.RefreshCookieOptions = cookieOptions
	s.AccessCookieOptions.SetName("access_token")
	if s.AccessCookieOptions.MaxAge == 0 {
		s.AccessCookieOptions.MaxAge = int(s.Validity.AccessExpiresIn)
	}
}

func (s *AuthOptions) SetAccessTokenClaims(username string, accessClaims *claims.JWTAccessClaims) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.accessTokenClaims == nil {
		s.accessTokenClaims = make(map[string]*claims.JWTAccessClaims)
	}
	s.accessTokenClaims[username] = accessClaims
}

func (s *AuthOptions) IsAccessTokenClaimsSet(username string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.accessTokenClaims == nil {
		return false
	}
	_, exists := s.accessTokenClaims[username]
	return exists
}

func (s *AuthOptions) GetAccessTokenClaims(username string) *claims.JWTAccessClaims {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.accessTokenClaims[username]
}
