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

func NewOAuthServer(kid string, kmanager manager.Manager, opt *options.AuthOptions) (*OAuthServer, error) {
	if opt == nil || opt.Validity == nil {
		opt = options.DefaultAuthOptions()
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
	f func(username string, password string, opt *options.AuthOptions)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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

		password := r.FormValue("password")
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
		claims := &claims.JWTClaims{
			AccessClaims: accessClaims,
		}

		// Function passed by user where they save the hashed password to db
		f(username, password, o.options)

		token, err := accessor.NewToken(ctx, access, claims, o.options)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"message": err.Error()})
			return
		}

		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(token)
	}
}
