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

func NewToken(ctx context.Context, a JWTAccess, c *claims.JWTClaims, opt *options.AuthOptions) (*Token, error) {
	key, err := GetParsedSigningKey(a)
	if err != nil {
		return nil, err
	}

	accessToken, err := GenerateAccessToken(a, c.AccessClaims, key)
	if err != nil {
		return nil, err
	}

	tok := &Token{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   opt.Validity.AccessExpiresIn,
	}

	if c.IdClaims != nil {
		idToken, err := GenerateIdToken(a, c.IdClaims, key)
		if err != nil {
			return nil, err
		}
		tok.IdToken = idToken
	}

	refreshExpiresIn := opt.Validity.RefreshExpiresIn
	if refreshExpiresIn != 0 {
		refresh, err := GenerateRefreshToken(ctx, accessToken, opt)
		if err != nil {
			return nil, err
		}
		tok.RefreshToken = refresh
	}

	return tok, nil
}

func GetParsedSigningKey(a JWTAccess) (interface{}, error) {
	signingMethod := a.GetSigningMethod()
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

	return key, nil
}

func GenerateAccessToken(a JWTAccess, accessClaims *claims.JWTAccessClaims, signingKey interface{}) (string, error) {
	token := jwt.NewWithClaims(a.GetSigningMethod(), accessClaims)
	token.Header["kid"] = a.GetSignedKeyID()
	accessToken, err := token.SignedString(signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}
	return accessToken, nil
}

func GenerateIdToken(a JWTAccess, idClaims *claims.JWTIdClaims, signingKey interface{}) (string, error) {
	idToken := jwt.NewWithClaims(a.GetSigningMethod(), idClaims)
	idToken.Header["kid"] = a.GetSignedKeyID()
	idString, err := idToken.SignedString(signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}
	return idString, nil
}

func GenerateRefreshToken(ctx context.Context, accessToken string, opt *options.AuthOptions) (string, error) {
	id := uuid.NewSHA1(uuid.New(), []byte(accessToken)).String()
	refresh := base64.URLEncoding.EncodeToString([]byte(id))
	expiry := opt.Validity.RefreshExpiresIn

	ti := &store.TokenInfo{
		ResourceOwnerId: id,
		AccessToken:     accessToken,
		Expiry:          time.Now().Add(time.Duration(expiry) * time.Second),
	}
	if err := opt.Store.StoreToken(ctx, ti); err != nil {
		return "", fmt.Errorf("failed to store token: %w", err)
	}

	return refresh, nil
}
