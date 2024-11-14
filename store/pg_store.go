package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

type PgTokenStore struct {
	Db *pgxpool.Pool
}

func NewPgTokenStore(ctx context.Context, databaseUrl string) (*PgTokenStore, error) {
	dbpool, err := pgxpool.New(ctx, databaseUrl)

	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	return &PgTokenStore{
		Db: dbpool,
	}, nil
}

func (s *PgTokenStore) CreateStore(ctx context.Context) error {
	query := `
	CREATE TABLE IF NOT EXISTS oauth_access_tokens (
		id SERIAL PRIMARY KEY,
		resource_owner_id UUID NOT NULL,
		access_token TEXT NOT NULL,
		expiry TIMESTAMPTZ NOT NULL
	);
	`
	_, err := s.Db.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to create table: %w", err)
	}
	return nil
}

func (s *PgTokenStore) StoreToken(ctx context.Context, tokenInfo *TokenInfo) error {
	query := "INSERT INTO oauth_access_tokens (resource_owner_id, access_token, expiry) VALUES ($1, $2, $3)"
	_, err := s.Db.Exec(ctx, query, tokenInfo.ResourceOwnerId, tokenInfo.AccessToken, tokenInfo.Expiry)
	if err != nil {
		return fmt.Errorf("failed to store token info: %w", err)
	}
	return nil
}

func (s *PgTokenStore) CloseConnection() {
	s.Db.Close()
}
