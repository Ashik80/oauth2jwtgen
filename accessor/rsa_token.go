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

type RS256Access struct {
	SignedKeyID   string
	SignedKey     []byte
	SigningMethod jwt.SigningMethod
}

func NewRS256Access(kid string, manager *manager.RSKeyManager) (*RS256Access, error) {
	key, err := manager.GetKey(kid)
	if err != nil {
		return nil, err
	}
	r := &RS256Access{
		SignedKeyID:   kid,
		SignedKey:     key,
		SigningMethod: jwt.SigningMethodRS256,
	}

	return r, nil
}

func (r *RS256Access) GetSigningKeyID() string {
	return r.SignedKeyID
}

func (r *RS256Access) GetSigningKey() []byte {
	return r.SignedKey
}

func (r *RS256Access) GetSigningMethod() jwt.SigningMethod {
	return r.SigningMethod
}

func (r *RS256Access) RenewToken(ctx context.Context, refreshToken string, signingKey string, opt *options.AuthOptions) (*Token, error) {
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

	publicKey, err := verifier.LoadRSAPublicKeyFromFile(signingKey)
	if err != nil {
		return nil, err
	}
	token, err := verifier.ParseRSToken(prevAccessToken, publicKey)
	if err != nil {
		if !IsExpiredError(err) {
			return nil, err
		}
	}

	accessClaims, err := GetClaimsWithUpdatedExpiry(token, opt)
	if err != nil {
		return nil, err
	}

	key, err := GetParsedSigningKey(r)
	if err != nil {
		return nil, err
	}
	accessToken, err := GenerateTokenString(r, accessClaims, key)
	if err != nil {
		return nil, err
	}

	t := &Token{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   accessClaims["exp"].(int64),
	}

	username := accessClaims["sub"].(string)

	if opt.IsIdTokenClaimsSet(username) {
		idClaims := opt.GetIdTokenClaims(username)
		idToken, err := GenerateTokenString(r, idClaims, []byte(signingKey))
		if err != nil {
			return nil, err
		}
		t.IdToken = idToken
	}

	err = opt.Store.UpdateTokenInfo(ctx, string(idBytes), accessToken, t.IdToken)
	if err != nil {
		return nil, err
	}

	return t, nil
}
