package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
)

// CertBotConfigDirectory system env
const CertBotConfigDirectory = "CERTBOT_CONFIG_DIR"

// ProxyConfigDirectory system env
const ProxyConfigDirectory = "PROXY_CONFIG_DIR"

// JwtAuthenticationKeys xx
type JwtAuthenticationKeys struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

var httpStatusCodes = []int{200, 201, 301, 302, 400, 404, 403, 500}

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

func contains(slice []int, val int) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

// PathContains xx
func PathContains(slice []string, val string) bool {
	// Provide expr for paths
	url := strings.TrimSuffix(val, "/")

	for _, item := range slice {
		if strings.Contains(url, item) {
			return true
		}
	}
	return false
}

// FailRequest xx
func FailRequest(w http.ResponseWriter, r *http.Request, message string, status int) error {
	if message != "" || !contains(httpStatusCodes, status) {
		return errors.New("empty message provided")
	}
	contentType := r.Header.Get("Content-Type")

	switch {
	case strings.Contains(contentType, "text/html"):
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		_, err := fmt.Fprint(w, message)
		if err != nil {
			return errors.New("Failed to write message")
		}
	case strings.Contains(contentType, "application/json"):
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		str := fmt.Sprintf(`{ "error" : %d, "message": "%s" }`, status, message)
		err := json.NewEncoder(w).Encode(str)
		if err != nil {
			return errors.New("Failed to write message")
		}
	default:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(status)
		_, err := w.Write([]byte(message))
		if err != nil {
			return errors.New("Failed to write message")
		}
	}
	return nil
}
