package store

import (
	"context"
	"sync"
)

type MemoryTokenStore struct {
	TokenInfos map[string]TokenInfo
	mu         sync.Mutex
}

func (s *MemoryTokenStore) CreateStore(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TokenInfos = make(map[string]TokenInfo)

	return nil
}

func (s *MemoryTokenStore) StoreToken(ctx context.Context, tokenInfo *TokenInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TokenInfos[tokenInfo.ResourceOwnerId] = *tokenInfo

	return nil
}

func (s *MemoryTokenStore) CloseConnection() error {
	s.mu.Lock()
	s.mu.Unlock()
	s.TokenInfos = nil

	return nil
}
