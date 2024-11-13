# oauth2jwtgen - An utility package for generating JWT tokens for OAuth2 authentication

This package can be used when developing an OAuth2 provider. Currently, the package can create tokens by properly signing them with HMAC or RSA signing methods. It provides built-in endpoint wrappers that returns OAuth2 tokens.

*NOTE: Only the Resource Owner Password Credential grant has been implemented so far*

## Default claims

By default the username is used as `sub`. The application using this package will be the `iss`

## Usage

Take a look at the `example.go` file

```go
package main

import (
	"fmt"
	"net/http"

	"github.com/Ashik80/oauth2jwtgen/accessor"
	"github.com/Ashik80/oauth2jwtgen/manager"
	"github.com/Ashik80/oauth2jwtgen/server"
)

func main() {
	m := manager.NewHSKeyManager()
	m.AddKey("key1", "sdfsdfsdfsdfasdfdsfasdfsdfasdf") // secrets should be stored in env variables
	// For RSA keys add the path to the key
	// Eg:
	//     m := manager.NewRSKeyManager()
	//     m.AddKey("key1", "keys/private.key")

	// By default validity of token is 10 minutes
	v := &accessor.Validity{
		ExpiresIn: 15 * 60, // 15 minutes
	}

	// Specify here which key to use. For example, we are using key1 here
	oauthServer := server.NewOAuthServer("key1", m, v)

	// Password grant flow endpoint example
	http.HandleFunc("POST /oauth2/token", oauthServer.ResourceOwnerPasswordCredential(func(username string, password string) {
		fmt.Printf("do something with %s and %s\n", username, password)
	}))

	http.ListenAndServe(":4040", nil)
}
```
