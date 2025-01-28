package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

type Claims struct {
	jwt.RegisteredClaims
}

// Using global private key for simplicity, it generated once and stored in memory
var privateKey *ecdsa.PrivateKey

var ExpireTime = time.Hour

func init() {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	privateKey = key
}

func NewToken(username string) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodES256, &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   username,
			Issuer:    "vpnlite",
			Audience:  jwt.ClaimStrings{"vpnlite"},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ExpireTime)),
		},
	}).SignedString(privateKey)
}

func ParseToken(tokenString string) (*Claims, error) {
	var claims Claims
	_, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (any, error) {
		return privateKey.Public(), nil
	}, jwt.WithAudience("vpnlite"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}
	return &claims, nil
}
