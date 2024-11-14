package main

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/Ashik80/oauth2jwtgen/accessor"
	"github.com/Ashik80/oauth2jwtgen/manager"
	"github.com/Ashik80/oauth2jwtgen/server"
	"github.com/Ashik80/oauth2jwtgen/store"
)

func main() {
	m := manager.NewHSKeyManager()
	m.AddKey("key1", "thesecret") // secrets should be stored in env variables
	// For RSA keys add the path to the key
	// Eg:
	//     m := manager.NewRSKeyManager()
	//     m.AddKey("key1", "keys/private.key")

	// By default validity of token is 10 minutes
	v := &accessor.Validity{
		ExpiresIn: 15 * 60, // 15 minutes
	}

	ctx := context.Background()

	// Create storage to save tokens. You can implement your own token storage.
	// As long as the store implements the TokenStore interface
	var s store.TokenStore
	var err error
	if s, err = store.NewPgTokenStore(ctx, "postgresql://postgres:postgres@localhost:5432/go_db"); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if err = s.CreateStore(ctx); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Specify here which key to use. For example, we are using key1 here
	oauthServer := server.NewOAuthServer("key1", m, v, s)

	// Password grant flow endpoint example
	http.HandleFunc(
		"POST /oauth2/token",
		oauthServer.ResourceOwnerPasswordCredential(ctx, func(username string, password string) {
			fmt.Printf("do something with %s and %s\n", username, password)
		}))

	http.ListenAndServe(":4040", nil)
}
