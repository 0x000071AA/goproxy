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

type UserInfo struct {
	UserName string
}

type JwtAuthClaims struct {
	*jwt.StandardClaims
	CsrfToken string
	UserInfo
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
		UserInfo{username},
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

type AuthenticationMiddleware struct {
	tokenUsers map[string]string
}

func (middleware *AuthenticationMiddleware) Populate() {
	middleware.tokenUsers["token"] = "user"
}

func (middleware *AuthenticationMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Session-Token")
		if user, found := middleware.tokenUsers[token]; found {
			next.ServeHTTP(w, r)
		} else {
			log.Printf("Forbidden for user %s\n", user)
			http.Error(w, "Forbidden", http.StatusForbidden)
		}
	})
}
