package server

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/Ashik80/oauth2jwtgen/accessor"
	"github.com/Ashik80/oauth2jwtgen/claims"
	"github.com/Ashik80/oauth2jwtgen/manager"
	"github.com/Ashik80/oauth2jwtgen/options"
)

type OAuthServer struct {
	kid      string
	kmanager manager.Manager
	options  *options.AuthOptions
}

type CallbackError struct {
	StatusCode int
	Message    string
}

func (c *CallbackError) Code() int {
	return c.StatusCode
}

func (c *CallbackError) Error() string {
	return c.Message
}

type AuthCallbackFunc func(r *http.Request, opt *options.AuthOptions) *CallbackError

func NewOAuthServer(kid string, kmanager manager.Manager, opt *options.AuthOptions) (*OAuthServer, error) {
	if opt.Store == nil {
		return nil, fmt.Errorf("token store not specified")
	}
	if opt.Validity == nil {
		opt.Validity = new(options.Validity)
		opt.Validity.SetDefaultAccessExpiresIn()
		opt.Validity.SetDefaultRefreshExpiresIn()
	}
	if opt.Validity.AccessExpiresIn == 0 {
		opt.Validity.SetDefaultAccessExpiresIn()
	}

	if opt.Store == nil {
		return nil, fmt.Errorf("token store not specified")
	}

	return &OAuthServer{
		kid:      kid,
		kmanager: kmanager,
		options:  opt,
	}, nil
}

func (o *OAuthServer) ResourceOwnerPasswordCredential(
	f func(r *http.Request, opt *options.AuthOptions) *CallbackError) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		w.Header().Add("Content-Type", "application/json")

		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		grantType := r.FormValue("grant_type")

		if grantType != "password" {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}

		// Function passed by user where they save the hashed password to db
		if err := f(r, o.options); err != nil {
			w.WriteHeader(err.StatusCode)
			json.NewEncoder(w).Encode(map[string]string{"message": err.Error()})
			return
		}

		username := r.FormValue("username")
		aud := r.Header.Get("Origin")

		var access accessor.JWTAccess
		var err error

		if man, ok := o.kmanager.(*manager.HSKeyManager); ok {
			access, err = accessor.NewHS256Access(o.kid, man)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
		} else if man, ok := o.kmanager.(*manager.RSKeyManager); ok {
			access, err = accessor.NewRS256Access(o.kid, man)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid key manager"})
			return
		}

		issuer := r.Host

		var scope string
		var roles []string
		if o.options.IsAccessTokenClaimsSet(username) {
			setClaims := o.options.GetAccessTokenClaims(username)
			scope = setClaims.Scope
			roles = setClaims.Roles
		}

		accessClaims := claims.GenerateAccessClaims(username, issuer, aud, scope, roles, o.options.Validity.AccessExpiresIn)
		c := &claims.JWTClaims{
			AccessClaims: accessClaims,
		}

		if o.options.IsIdTokenClaimsSet(username) {
			c.IdClaims = o.options.GetIdTokenClaims(username)
			c.IdClaims.MapClaims(accessClaims)
		}

		token, err := accessor.NewToken(ctx, access, c, o.options)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"message": err.Error()})
			return
		}

		if o.options.IsRefreshTokenInCookie() {
			refreshCookie := SetCookie(o.options.GetRefreshCookieOptions(), token.RefreshToken)
			http.SetCookie(w, refreshCookie)
		}

		if o.options.IsAccessTokenInCookie() {
			accessCookie := SetCookie(o.options.GetAccessCookieOptions(), token.AccessToken)
			http.SetCookie(w, accessCookie)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(token)
	}
}

func SetCookie(cookieOptions *options.CookieOptions, value string) *http.Cookie {
	return &http.Cookie{
		Name:     cookieOptions.GetName(),
		Value:    value,
		Secure:   cookieOptions.Secure,
		HttpOnly: cookieOptions.HttpOnly,
		MaxAge:   cookieOptions.MaxAge,
		Path:     cookieOptions.Path,
		SameSite: cookieOptions.SameSite,
	}
}
