package server

import (
	"encoding/json"
	"net/http"

	"github.com/Ashik80/oauth2jwtgen/accessor"
	"github.com/Ashik80/oauth2jwtgen/manager"
)

type OAuthServer struct {
	kid      string
	kmanager manager.Manager
	validity *accessor.Validity
}

func NewOAuthServer(kid string, kmanager manager.Manager, validity *accessor.Validity) *OAuthServer {
	return &OAuthServer{
		kid, kmanager, validity,
	}
}

func (o *OAuthServer) ResourceOwnerPasswordCredential(f func(username string, password string)) http.HandlerFunc {
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

		claims := accessor.GenerateClaims(access, username, issuer, aud)
		token, err := accessor.NewToken(access, claims)

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"message": err.Error()})
			return
		}

		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(token)
	}
}
