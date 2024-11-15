# oauth2jwtgen - An utility package for generating JWT tokens for OAuth2 authentication

This package can be used when developing an OAuth2 provider. Currently, the package can create tokens by properly signing them with HMAC or RSA signing methods. It provides built-in endpoint wrappers that returns OAuth2 tokens.

*NOTE: Only the Resource Owner Password Credential grant has been implemented so far*

## Default claims

By default the username is used as `sub`. The application using this package will be the `iss`

## Usage

1. Initialize key manager

The following example is fo a HMAC signed key. The first step is to initialize a key manager and add a key

```go
keyManager := manager.NewHSKeyManager()
keyManager.AddKey("key1", "thesecret")
```

2. Set up token storage

Then define and create a token storage. For now, the package implements postgres storage. You can implement your own token storage but it must implement the TokenStorage interface.

```go
s, _ = store.NewPgTokenStore(ctx, "postgresql://postgres:postgres@localhost:5432/go_db")
s.CreateStore(ctx)
```

The TokenStore interface
```go
type TokenStore interface {
	CloseConnection()
	CreateStore(ctx context.Context) error
	StoreToken(ctx context.Context, tokenInfo *TokenInfo) error
}
```

3. Create the server obejct

And then we can initialize oauth server with the key manager

```go
oauthServer := server.NewOAuthServer("key1", keyManager, nil, s)
```

4. Define the endpoint

Then we can call the password grant endpoint like this

```go
http.HandleFunc(
    "POST /oauth2/token",
    oauthServer.ResourceOwnerPasswordCredential(ctx, func(username string, password string) {
        fmt.Printf("do something with %s and %s\n", username, password)
    }))
```

## Example

Take a look at the `example.go` file

```go
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
```
