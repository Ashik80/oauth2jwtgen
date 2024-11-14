package accessor

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/Ashik80/oauth2jwtgen/store"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

type Validity struct {
	ExpiresIn int64
}

type Token struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
}

type JWTAccess interface {
	GetSignedKeyID() string
	GetSignedKey() []byte
	GetSigningMethod() jwt.SigningMethod
	GetExpiresIn() int64
}

func NewToken(ctx context.Context, a JWTAccess, claims *JWTAccessClaims, s store.TokenStore) (*Token, error) {
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

	id := uuid.NewSHA1(uuid.New(), []byte(access)).String()
	refresh := base64.URLEncoding.EncodeToString([]byte(id))

	ti := &store.TokenInfo{
		ResourceOwnerId: id,
		AccessToken:     access,
		Expiry:          time.Now().Add(time.Duration(15 * 60)),
	}
	if err = s.StoreToken(ctx, ti); err != nil {
		return nil, err
	}

	return &Token{
		AccessToken:  access,
		TokenType:    "Bearer",
		RefreshToken: refresh,
		ExpiresIn:    a.GetExpiresIn(),
	}, nil
}
