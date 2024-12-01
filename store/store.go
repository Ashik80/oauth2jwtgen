package store

import (
	"context"
	"time"
)

type TokenStore interface {
	CreateStore(ctx context.Context) error
	StoreToken(ctx context.Context, tokenInfo *TokenInfo) error
	GetTokenInfo(ctx context.Context, resourceOwnerId string) (*TokenInfo, error)
	CloseConnection() error
}

type TokenInfo struct {
	Id              int64
	ResourceOwnerId string
	AccessToken     string
	IdToken         *string
	Expiry          time.Time
}
