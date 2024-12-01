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
	GetSigningKeyID() string
	GetSigningKey() []byte
	GetSigningMethod() jwt.SigningMethod
	RenewToken(ctx context.Context, refreshToken string, signingKey string, opt *options.AuthOptions) (*Token, error)
}

// Returns the token object (or an error) that consists of id, access and refresh tokens
func NewToken(ctx context.Context, a JWTAccess, c *claims.JWTClaims, opt *options.AuthOptions) (*Token, error) {
	key, err := GetParsedSigningKey(a)
	if err != nil {
		return nil, err
	}

	accessToken, err := GenerateTokenString(a, c.AccessClaims, key)
	if err != nil {
		return nil, err
	}

	tok := &Token{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   opt.Validity.AccessExpiresIn,
	}

	if c.IdClaims != nil {
		idToken, err := GenerateTokenString(a, c.IdClaims, key)
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
	signingKey := a.GetSigningKey()

	var key interface{}
	if strings.HasPrefix(signingMethod.Alg(), "RS") {
		privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(signingKey)
		if err != nil {
			return nil, fmt.Errorf("error parsing RSA key: %w", err)
		}
		key = privateKey
	} else if strings.HasPrefix(signingMethod.Alg(), "HS") {
		key = signingKey
	}

	return key, nil
}

func GenerateTokenString(a JWTAccess, accessClaims jwt.Claims, signingKey interface{}) (string, error) {
	token := jwt.NewWithClaims(a.GetSigningMethod(), accessClaims)
	token.Header["kid"] = a.GetSigningKeyID()
	accessToken, err := token.SignedString(signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}
	return accessToken, nil
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

func IsExpiredError(err error) bool {
	if vErr, ok := err.(*jwt.ValidationError); !ok || vErr.Errors&jwt.ValidationErrorExpired != 16 {
		return false
	}
	return true
}

func GetClaimsWithUpdatedExpiry(token *jwt.Token, opt *options.AuthOptions) (jwt.MapClaims, error) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("failed to get claims")
	}
	if opt.Validity == nil {
		v := &options.Validity{}
		v.SetDefaultAccessExpiresIn()
		opt.Validity = v
	}
	newIat := time.Now().UTC().Unix()
	newExp := newIat + opt.Validity.AccessExpiresIn
	claims["iat"] = newIat
	claims["exp"] = newExp
	return claims, nil
}
