package accessor

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/Ashik80/oauth2jwtgen/claims"
	"github.com/Ashik80/oauth2jwtgen/options"
	"github.com/Ashik80/oauth2jwtgen/store"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

type Token struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type,omitempty"`
	IdToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
}

type JWTAccess interface {
	GetSignedKeyID() string
	GetSignedKey() []byte
	GetSigningMethod() jwt.SigningMethod
}

func NewToken(ctx context.Context, a JWTAccess, claims *claims.JWTClaims, opt *options.AuthOptions) (*Token, error) {
	signingMethod := a.GetSigningMethod()
	signedKey := a.GetSignedKey()

	// get appropriate signing key
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

	// generate access token
	token := jwt.NewWithClaims(signingMethod, claims.AccessClaims)
	token.Header["kid"] = a.GetSignedKeyID()
	access, err := token.SignedString(key)
	if err != nil {
		return nil, fmt.Errorf("failed to sign token: %w", err)
	}

	tok := &Token{
		AccessToken: access,
		TokenType:   "Bearer",
		ExpiresIn:   opt.Validity.AccessExpiresIn,
	}

	// generate id token
	if claims.IdClaims != nil {
		idToken := jwt.NewWithClaims(signingMethod, claims.IdClaims)
		idToken.Header["kid"] = a.GetSignedKeyID()
		idstring, err := token.SignedString(key)
		if err != nil {
			return nil, fmt.Errorf("failed to sign token: %w", err)
		}
		tok.IdToken = idstring
	}

	// generate refresh token
	refreshExpiresIn := opt.Validity.RefreshExpiresIn
	if refreshExpiresIn != 0 {
		id := uuid.NewSHA1(uuid.New(), []byte(access)).String()
		refresh := base64.URLEncoding.EncodeToString([]byte(id))

		ti := &store.TokenInfo{
			ResourceOwnerId: id,
			AccessToken:     access,
			Expiry:          time.Now().Add(time.Duration(refreshExpiresIn) * time.Second),
		}
		if err = opt.Store.StoreToken(ctx, ti); err != nil {
			return nil, err
		}
		tok.RefreshToken = refresh
	}

	return tok, nil
}
