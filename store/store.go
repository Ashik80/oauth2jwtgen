package store

import (
	"context"
	"time"
)

type TokenStore interface {
	CloseConnection()
	CreateStore(ctx context.Context) error
	StoreToken(ctx context.Context, tokenInfo *TokenInfo) error
}

type TokenInfo struct {
	Id              int64
	ResourceOwnerId string
	AccessToken     string
	Expiry          time.Time
}
