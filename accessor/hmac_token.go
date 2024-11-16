package accessor

import (
	"github.com/Ashik80/oauth2jwtgen/manager"

	"github.com/golang-jwt/jwt"
)

type HS256Access struct {
	SignedKeyID      string
	SignedKey        []byte
	SigningMethod    jwt.SigningMethod
	AccessExpiresIn  int64
	RefreshExpiresIn int64
}

func NewHS256Access(kid string, manager *manager.HSKeyManager, validity *Validity) (*HS256Access, error) {
	key, err := manager.GetKey(kid)
	if err != nil {
		return nil, err
	}

	a := &HS256Access{
		SignedKeyID:      kid,
		SignedKey:        key,
		SigningMethod:    jwt.SigningMethodHS256,
		AccessExpiresIn:  validity.AccessExpiresIn,
		RefreshExpiresIn: validity.RefreshExpiresIn,
	}

	return a, nil
}

func (h *HS256Access) GetSignedKeyID() string {
	return h.SignedKeyID
}

func (h *HS256Access) GetSignedKey() []byte {
	return h.SignedKey
}

func (h *HS256Access) GetAccessExpiresIn() int64 {
	return h.AccessExpiresIn
}

func (h *HS256Access) GetRefreshExpiresIn() int64 {
	return h.RefreshExpiresIn
}

func (h *HS256Access) GetSigningMethod() jwt.SigningMethod {
	return h.SigningMethod
}
