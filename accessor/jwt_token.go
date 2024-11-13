package accessor

import (
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
)

type Validity struct {
	ExpiresIn int64
}

type Token struct {
	AccessToken string `json:"access_token"`

	// TokenType is the type of token.
	// The Type method returns either this or "Bearer", the default.
	TokenType string `json:"token_type,omitempty"`

	RefreshToken string `json:"refresh_token,omitempty"`

	// Expiry is the optional expiration time of the access token.
	//
	// If zero, TokenSource implementations will reuse the same
	// token forever and RefreshToken or equivalent
	// mechanisms for that TokenSource will not be used.
	Expiry time.Time `json:"expiry,omitempty"`

	// ExpiresIn is the OAuth2 wire format "expires_in" field,
	// which specifies how many seconds later the token expires,
	// relative to an unknown time base approximately around "now".
	// It is the application's responsibility to populate
	// `Expiry` from `ExpiresIn` when required.
	ExpiresIn int64 `json:"expires_in,omitempty"`
	// contains filtered or unexported fields
}

type JWTAccess interface {
	GetSignedKeyID() string
	GetSignedKey() []byte
	GetSigningMethod() jwt.SigningMethod
	GetExpiresIn() int64
}

func NewToken(a JWTAccess, claims *JWTAccessClaims) (*Token, error) {
	signingMethod := a.GetSigningMethod()

	token := jwt.NewWithClaims(signingMethod, claims)

	signedKey := a.GetSignedKey()

	var key interface{}
	if strings.HasPrefix(signingMethod.Alg(), "RS") {
		privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(signedKey)
		if err != nil {
			return nil, fmt.Errorf("error parsing RSA key: %w", err)
		}
		key = privateKey
	} else if strings.HasPrefix(signingMethod.Alg(), "HS") {
		key = signedKey
	}

	token.Header["kid"] = a.GetSignedKeyID()

	access, err := token.SignedString(key)
	if err != nil {
		return nil, fmt.Errorf("failed to sign token: %w", err)
	}

	return &Token{
		AccessToken:  access,
		TokenType:    "Bearer",
		RefreshToken: "sdfsdfsdf",
		ExpiresIn:    a.GetExpiresIn(),
	}, nil
}
