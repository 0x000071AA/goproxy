package main

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

type JwtAuthClaims struct {
	*jwt.StandardClaims
	CsrfToken string
}

var jwtExpiresAt = time.Now().Add(time.Hour * 5).Unix()

// RefreshJwtToken check if token expires and refreshes it
func RefreshJwtToken(tokenString, username string, privateKey *rsa.PrivateKey) (string, error) {
	exp := time.Unix(jwtExpiresAt, 0).Sub(time.Now())

	if exp > 30*time.Second {
		return tokenString, nil
	}
	return JwtRSATokenHandler(username, privateKey)
}

// JwtRSATokenHandler xx
func JwtRSATokenHandler(username string, privateKey *rsa.PrivateKey) (string, error) {
	csrfToken, err := GenerateRandomString(12)
	if err != nil {
		return "", err
	}

	token := jwt.New(jwt.SigningMethodRS512)
	token.Claims = &JwtAuthClaims{
		&jwt.StandardClaims{
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: jwtExpiresAt,
		},
		csrfToken,
	}
	return token.SignedString(privateKey)
}

// JwtRSATokenValidatorHandler xx
func JwtRSATokenValidatorHandler(tokenString string, publicKey *rsa.PublicKey) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("Error while parsing token: %v", err)
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("Invalid token")
}

// JwtHAMACTokenHandler for testing only
func JwtHAMACTokenHandler(username string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user": username,
		"exp":  time.Now().Add(time.Hour * time.Duration(5)).Unix(),
		"iat":  time.Now().Unix(),
	})

	tokenString, err := token.SignedString([]byte("SECRET_API_KEY"))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// JwtHAMACValidationHandler for testing only
func JwtHAMACValidationHandler(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte("SECRET_API_KEY"), nil
	})
	if err != nil {
		return nil, fmt.Errorf("Error while parsing token: %v", err)
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("Invalid token")
}

// AuthenticationMiddleware xx
func AuthenticationMiddleware(config TargetHostConfig) func(next http.Handler) http.Handler {
	passthrough := config.Passthrough
	allowedPaths := config.AllowedPaths
	paths := config.Paths
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if passthrough {
				next.ServeHTTP(w, r)
				return
			}
			url := r.URL.RequestURI()
			if PathContains(allowedPaths, url) {
				next.ServeHTTP(w, r)
				return
			} else if !PathContains(paths, url) {
				FailRequest(w, r, "Forbidden", http.StatusForbidden)
				return
			}

			token := r.Header.Get("X-Session-Token")
			if token == "" {
				FailRequest(w, r, "Forbidden", http.StatusForbidden)
				return
			}

			pubKey, err := ParsePublicKey()

			jwt, err := JwtRSATokenValidatorHandler(token, nil)
			if err != nil {
				log.Printf("Forbidden for user %s\n", token)
				FailRequest(w, r, "Forbidden", http.StatusForbidden)
			}
			log.Printf("%T", jwt)
			next.ServeHTTP(w, r)
		})
	}
}
