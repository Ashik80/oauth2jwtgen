package server

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/Ashik80/oauth2jwtgen/accessor"
	"github.com/Ashik80/oauth2jwtgen/manager"
	"github.com/Ashik80/oauth2jwtgen/store"
)

type OAuthServer struct {
	kid      string
	kmanager manager.Manager
	validity *accessor.Validity
	store    store.TokenStore
}

func NewOAuthServer(kid string, kmanager manager.Manager, validity *accessor.Validity, store store.TokenStore) *OAuthServer {
	return &OAuthServer{
		kid, kmanager, validity, store,
	}
}

func (o *OAuthServer) ResourceOwnerPasswordCredential(ctx context.Context, f func(username string, password string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer o.store.CloseConnection()

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

		// Function passed by user where they save the hashed password to db
		f(username, password)

		var access accessor.JWTAccess
		var err error

		if man, ok := o.kmanager.(*manager.HSKeyManager); ok {
			access, err = accessor.NewHS256Access(o.kid, man, o.validity)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
		} else if man, ok := o.kmanager.(*manager.RSKeyManager); ok {
			access, err = accessor.NewRS256Access(o.kid, man, o.validity)
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

		claims := accessor.GenerateClaims(access, username, issuer, aud, scope)
		token, err := accessor.NewToken(ctx, access, claims, o.store)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"message": err.Error()})
			return
		}

		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(token)
	}
}
