package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/Ashik80/oauth2jwtgen/accessor"
	"github.com/Ashik80/oauth2jwtgen/manager"
	"github.com/Ashik80/oauth2jwtgen/options"
	"github.com/Ashik80/oauth2jwtgen/server"
	"github.com/Ashik80/oauth2jwtgen/store"
)

func main() {
	secretKey := "thesecret" // secrets should be stored in env variables

	m := manager.NewHSKeyManager()
	m.AddKey("key1", secretKey)
	// For RSA keys add the path to the key
	// Eg:
	//     m := manager.NewRSKeyManager()
	//     m.AddKey("key1", "keys/private.key")

	// By default validity of access token is 10 minutes
	// and refresh token is 1 hour
	v := &options.Validity{
		AccessExpiresIn:  15 * 60, // 15 minutes
		RefreshExpiresIn: 30 * 60, // 30 minutes
	}

	ctx := context.Background()

	// Create storage to save tokens
	s := new(store.MemoryTokenStore)
	if err := s.CreateStore(ctx); err != nil {
		log.Fatalf("%v", err)
	}

	// Set the options for the Auth server
	o := &options.AuthOptions{
		Validity: v,
		Store:    s,
	}

	// Set this option if you want to save the refresh or access token in a cookie
	// NOTE: for mobile use a header to pass the refresh token as cookies won't work
	o.SetRefreshTokenInCookie(&options.CookieOptions{
		Secure:   false, // set to true in production
		HttpOnly: true,
		Path:     "/",
		MaxAge:   v.GetRefreshExpiresIn(),
	})

	// Specify here which key to use. For example, we are using key1 here
	oauthServer, err := server.NewOAuthServer("key1", m, o)
	if err != nil {
		log.Fatalf("%v", err)
	}

	mux := http.NewServeMux()

	// Password grant flow endpoint example
	mux.HandleFunc(
		"POST /oauth2/token",
		oauthServer.ResourceOwnerPasswordCredential(
			func(r *http.Request, opt *options.AuthOptions) *server.CallbackError {
				username := r.FormValue("username")
				password := r.FormValue("password")
				fmt.Printf("do something with %s and %s\n", username, password)
				return nil
			}))

	// Renew token flow endpoint example
	mux.HandleFunc(
		"GET /oauth2/refresh-token",
		func(w http.ResponseWriter, r *http.Request) {
			refreshCookie, _ := r.Cookie("refresh_token")
			acc, _ := accessor.NewHS256Access("key1", m)
			token, _ := acc.RenewToken(r.Context(), refreshCookie.Value, secretKey, o)
			w.Header().Add("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(token)
		})

	http.ListenAndServe(":4040", enableCors(mux))
}

func enableCors(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Access-Control-Allow-Origin", "http://localhost:3000")
		w.Header().Add("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		w.Header().Add("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Add("Access-Control-Allow-Credentials", "true") // important for if using cookie
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}
