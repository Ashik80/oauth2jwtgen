package manager

import (
	"fmt"
	"os"
	"sync"
)

type RSKeyManager struct {
	Keys map[string]string
	mu   sync.Mutex
}

func NewRSKeyManager() *RSKeyManager {
	return &RSKeyManager{
		Keys: make(map[string]string),
	}
}

func (m *RSKeyManager) AddKey(kid, path string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Keys[kid] = path
}

func (m *RSKeyManager) GetKey(kid string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	path, exists := m.Keys[kid]
	if !exists {
		return nil, fmt.Errorf("key does not exist")
	}
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}
	return key, nil
}
