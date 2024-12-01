package verifier

import (
	"fmt"

	"github.com/golang-jwt/jwt"
)

func VerifyHSToken(tokenString string, signingKey string) (jwt.MapClaims, error) {
	token, err := ParseHSToken(tokenString, signingKey)
	if err != nil {
		return nil, fmt.Errorf("error parsing token: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, fmt.Errorf("invalid token or claim")
	}
}

func ParseHSToken(tokenString string, signingKey string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(signingKey), nil
	})
	return token, err
}
