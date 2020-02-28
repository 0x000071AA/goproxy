package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
)

type JwtAuthenticationKeys struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// GenerateRandomBytes xx
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

// GenerateRandomString xx
func GenerateRandomString(s int) (string, error) {
	b, err := GenerateRandomBytes(s)
	return base64.URLEncoding.EncodeToString(b), err
}

// ParsePrivateKey xx
func ParsePrivateKey(location string) (*rsa.PrivateKey, error) {
	key, e := ioutil.ReadFile(location)
	if e != nil {
		return nil, fmt.Errorf("Unable to read private key: %v", e)
	}
	parsedKey, err := jwt.ParseRSAPrivateKeyFromPEM(key)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse private key: %v", err)
	}
	return parsedKey, nil
}

// ParsePublicKey xx
func ParsePublicKey(location string) (*rsa.PublicKey, error) {
	key, e := ioutil.ReadFile(location)
	if e != nil {
		return nil, fmt.Errorf("Unable to read public key: %v", e)
	}
	parsedKey, err := jwt.ParseRSAPublicKeyFromPEM(key)
	if err != nil {
		return nil, fmt.Errorf("Unable to read public key: %v", e)
	}
	return parsedKey, nil
}

// SingleJoiningSlash eliminates multiple slashes and leading slash
func SingleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}
