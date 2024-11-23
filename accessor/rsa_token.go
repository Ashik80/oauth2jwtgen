package accessor

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

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

func LoadRSAPublicKeyFromFile(filePath string) (*rsa.PublicKey, error) {
	pubKeyFile, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	block, _ := pem.Decode(pubKeyFile)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to parse PEM block containing the public key")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return rsaPubKey, nil
}

func VerifyRSToken(tokenString string, filePath string) (jwt.MapClaims, error) {
	publicKey, err := LoadRSAPublicKeyFromFile(filePath)
	if err != nil {
		return nil, err
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("error parsing token: %v", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, fmt.Errorf("invalid token or claim")
	}
}
