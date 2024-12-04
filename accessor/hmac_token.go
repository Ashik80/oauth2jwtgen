package accessor

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/Ashik80/oauth2jwtgen/manager"
	"github.com/Ashik80/oauth2jwtgen/options"
	"github.com/Ashik80/oauth2jwtgen/verifier"

	"github.com/golang-jwt/jwt"
)

type HS256Access struct {
	SigningKeyID  string
	SigningKey    []byte
	SigningMethod jwt.SigningMethod
}

func NewHS256Access(kid string, manager *manager.HSKeyManager) (*HS256Access, error) {
	key, err := manager.GetKey(kid)
	if err != nil {
		return nil, err
	}

	a := &HS256Access{
		SigningKeyID:  kid,
		SigningKey:    key,
		SigningMethod: jwt.SigningMethodHS256,
	}

	return a, nil
}

func (h *HS256Access) GetSigningKeyID() string {
	return h.SigningKeyID
}

func (h *HS256Access) GetSigningKey() []byte {
	return h.SigningKey
}

func (h *HS256Access) GetSigningMethod() jwt.SigningMethod {
	return h.SigningMethod
}

func (h *HS256Access) RenewToken(ctx context.Context, refreshToken string, signingKey string, opt *options.AuthOptions) (*Token, error) {
	idBytes, err := base64.URLEncoding.DecodeString(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decode token: %w", err)
	}

	tokenInfo, err := opt.Store.GetTokenInfo(ctx, string(idBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to get token info: %w", err)
	}

	if tokenInfo.Expiry.Before(time.Now()) {
		return nil, fmt.Errorf("refresh token expired")
	}

	prevAccessToken := tokenInfo.AccessToken
	token, err := verifier.ParseHSToken(prevAccessToken, signingKey)
	if err != nil {
		if !IsExpiredError(err) {
			return nil, err
		}
	}

	accessClaims, err := GetClaimsWithUpdatedExpiry(token, opt)
	if err != nil {
		return nil, err
	}

	key, err := GetParsedSigningKey(h)
	if err != nil {
		return nil, err
	}
	accessToken, err := GenerateTokenString(h, accessClaims, key)
	if err != nil {
		return nil, err
	}

	t := &Token{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   accessClaims["exp"].(int64),
	}

	username := accessClaims["sub"].(string)
	fmt.Println(accessClaims["sub"])

	if opt.IsIdTokenClaimsSet(username) {
		idClaims := opt.GetIdTokenClaims(username)
		idToken, err := GenerateTokenString(h, idClaims, key)
		if err != nil {
			return nil, err
		}
		t.IdToken = idToken
	}

	return t, nil
}
