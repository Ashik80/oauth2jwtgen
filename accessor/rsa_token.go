package accessor

import (
	"github.com/Ashik80/oauth2jwtgen/manager"

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

func (r *RS256Access) GetSignedKeyID() string {
	return r.SignedKeyID
}

func (r *RS256Access) GetSignedKey() []byte {
	return r.SignedKey
}

func (r *RS256Access) GetSigningMethod() jwt.SigningMethod {
	return r.SigningMethod
}
