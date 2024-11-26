package server

import (
	"context"
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
	ctx context.Context,
	f func(r *http.Request, opt *options.AuthOptions) *CallbackError) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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

		username := r.FormValue("username")
		aud := r.FormValue("client_id")
		scope := r.FormValue("scope")

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

		accessClaims := claims.GenerateClaims(username, issuer, aud, scope, o.options.Validity.AccessExpiresIn)
		c := &claims.JWTClaims{
			AccessClaims: accessClaims,
		}

		// Function passed by user where they save the hashed password to db
		if err := f(r, o.options); err != nil {
			w.WriteHeader(err.StatusCode)
			json.NewEncoder(w).Encode(map[string]string{"message": err.Error()})
			return
		}

		if o.options.IsIdTokenClaimsSet() {
			c.IdClaims = o.options.GetIdToken()
			claims.CopyStandardClaims(&c.IdClaims.StandardClaims, &accessClaims.StandardClaims)
		}

		token, err := accessor.NewToken(ctx, access, c, o.options)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"message": err.Error()})
			return
		}

		json.NewEncoder(w).Encode(token)
	}
}
