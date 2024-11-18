package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/Ashik80/oauth2jwtgen/manager"
	"github.com/Ashik80/oauth2jwtgen/options"
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

	// Specify here which key to use. For example, we are using key1 here
	oauthServer, err := server.NewOAuthServer("key1", m, o)
	if err != nil {
		log.Fatalf("%v", err)
	}

	// Password grant flow endpoint example
	http.HandleFunc(
		"POST /oauth2/token",
		oauthServer.ResourceOwnerPasswordCredential(
			ctx,
			func(username string, password string, opt *options.AuthOptions) *server.CallbackError {
				fmt.Printf("do something with %s and %s\n", username, password)
				return nil
			}))

	http.ListenAndServe(":4040", nil)
}
