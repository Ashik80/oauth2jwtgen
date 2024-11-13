package manager

import (
	"fmt"
	"sync"
)

type HSKeyManager struct {
	Keys map[string]string
	mu   sync.Mutex
}

func NewHSKeyManager() *HSKeyManager {
	return &HSKeyManager{
		Keys: make(map[string]string),
	}
}

func (m *HSKeyManager) AddKey(kid, secret string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Keys[kid] = secret
}

func (m *HSKeyManager) GetKey(kid string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key, exists := m.Keys[kid]
	if !exists {
		return nil, fmt.Errorf("key does not exist")
	}
	return []byte(key), nil
}
