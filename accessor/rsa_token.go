package accessor

import (
	"github.com/Ashik80/oauth2jwtgen/manager"

	"github.com/golang-jwt/jwt"
)

type RS256Access struct {
	SignedKeyID   string
	SignedKey     []byte
	SigningMethod jwt.SigningMethod
	ExpiresIn     int64
}

func NewRS256Access(kid string, manager *manager.RSKeyManager, validity *Validity) (*RS256Access, error) {
	key, err := manager.GetKey(kid)
	if err != nil {
		return nil, err
	}
	r := &RS256Access{
		SignedKeyID:   kid,
		SignedKey:     key,
		SigningMethod: jwt.SigningMethodRS256,
	}

	if validity != nil {
		r.ExpiresIn = validity.ExpiresIn
	} else {
		r.ExpiresIn = int64(10 * 60)
	}

	return r, nil
}

func (r *RS256Access) GetSignedKeyID() string {
	return r.SignedKeyID
}

func (r *RS256Access) GetSignedKey() []byte {
	return r.SignedKey
}

func (r *RS256Access) GetExpiresIn() int64 {
	return r.ExpiresIn
}

func (r *RS256Access) GetSigningMethod() jwt.SigningMethod {
	return r.SigningMethod
}
