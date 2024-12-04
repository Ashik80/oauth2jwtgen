package store

import (
	"context"
	"errors"
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

func (s *MemoryTokenStore) GetTokenInfo(ctx context.Context, resourceOwnerId string) (*TokenInfo, error) {
	tokenInfo, exists := s.TokenInfos[resourceOwnerId]
	if !exists {
		return nil, errors.New("token info not found")
	}
	return &tokenInfo, nil
}

func (s *MemoryTokenStore) UpdateTokenInfo(ctx context.Context, resourceOwnerId string, accessToken string, idToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tokenInfo, exists := s.TokenInfos[resourceOwnerId]
	if !exists {
		return errors.New("token info not found")
	}
	tokenInfo.AccessToken = accessToken
	if idToken != "" {
		tokenInfo.IdToken = &idToken
	}
	s.TokenInfos[resourceOwnerId] = tokenInfo
	return nil
}

func (s *MemoryTokenStore) CloseConnection() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TokenInfos = nil

	return nil
}
