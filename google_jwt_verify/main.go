package main

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

// Google JWKS URL
const googleJWKSURL = "https://www.googleapis.com/oauth2/v3/certs"

// JWKS Struct
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK (JSON Web Key) struct
type JWK struct {
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

// JWT Claims
type GoogleClaims struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	jwt.RegisteredClaims
}

// Fetch JWKS from Google
func getGoogleJWKS() (*JWKS, error) {
	resp, err := http.Get(googleJWKSURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS response: %w", err)
	}

	var jwks JWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	return &jwks, nil
}

// Get RSA Public Key from JWKS
func getRSAPublicKey(jwks *JWKS, kid string) (*rsa.PublicKey, error) {
	for _, key := range jwks.Keys {
		if key.Kid == kid {
			nBytes, err := jwt.DecodeSegment(key.N)
			if err != nil {
				return nil, fmt.Errorf("failed to decode modulus: %w", err)
			}
			eBytes, err := jwt.DecodeSegment(key.E)
			if err != nil {
				return nil, fmt.Errorf("failed to decode exponent: %w", err)
			}

			// Convert exponent from bytes to int
			e := 0
			for _, b := range eBytes {
				e = e<<8 + int(b)
			}

			// Convert modulus and exponent into RSA Public Key
			pubKey := &rsa.PublicKey{
				N: new(big.Int).SetBytes(nBytes),
				E: e,
			}

			return pubKey, nil
		}
	}
	return nil, errors.New("matching key not found")
}

// Parse and Verify JWT
func parseJWT(tokenString string) (*GoogleClaims, *rsa.PublicKey, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, nil, errors.New("invalid JWT format")
	}

	// Parse the JWT Header to get 'kid'
	headerSegment, err := jwt.DecodeSegment(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerSegment, &header); err != nil {
		return nil, nil, fmt.Errorf("failed to parse header: %w", err)
	}

	// Get Google's JWKS
	jwks, err := getGoogleJWKS()
	if err != nil {
		return nil, nil, err
	}

	// Find the matching RSA public key
	pubKey, err := getRSAPublicKey(jwks, header.Kid)
	if err != nil {
		return nil, nil, err
	}

	// Parse and validate the JWT
	token, err := jwt.ParseWithClaims(tokenString, &GoogleClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return pubKey, nil
	})
	if err != nil {
		return nil, nil, err
	}

	// Extract claims
	claims, ok := token.Claims.(*GoogleClaims)
	if !ok || !token.Valid {
		return nil, nil, errors.New("invalid JWT")
	}

	return claims, pubKey, nil
}

func main() {
	// Replace with an actual JWT for testing
	jwtToken := "eyJhbGciOiJSUzI1NiIsImtpZCI6IjI1ZjgyMTE3MTM3ODhiNjE0NTQ3NGI1MDI5YjAxNDFiZDViM2RlOWMiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI4MjUyOTU1NTY0MDAtNmhjdmgzb2Qwcm04NnZrOGFsZGVqZmpxaWJkaWxkZmUuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI4MjUyOTU1NTY0MDAtNmhjdmgzb2Qwcm04NnZrOGFsZGVqZmpxaWJkaWxkZmUuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDA3MDM2NzgwMzY2NDg5OTIxMjYiLCJlbWFpbCI6InNvZWRlcmJveUBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfaGFzaCI6IkJ5UHJZZ3FRRHZtSFJUc0MtQmdlUXciLCJuYW1lIjoiS2kgQWdlbmcgU2F0cmlhIFBhbXVuZ2thcyIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQ2c4b2NLSjE1anhMdkhHTUh1YWNNLXFLcU5BcnlqQ3pwY2c2UjlHa25wdWZUOU5qaGxJSkJfcD1zOTYtYyIsImdpdmVuX25hbWUiOiJLaSBBZ2VuZyBTYXRyaWEiLCJmYW1pbHlfbmFtZSI6IlBhbXVuZ2thcyIsImlhdCI6MTc0MTI4MzgwMiwiZXhwIjoxNzQxMjg3NDAyfQ.Fy8lz-sMy7tTb-ffupqbkj--zv8p1kribLBQgJuB7JG-tNPD-al7-UBkFq2gOqrK5V8rsXVdt6zLfApcTA14aaknI_cScbV812RUrf2un3XIcS2pixPU6D0QbBKyYmJg_2lovsKHFuMHEAKFMqvVur47KhkQukeMF0zF6Y0utJwyPCw5ay8a_QP0qPXQuKJyKJvXBQ_YLr0Cb0cWLX81W46v3z_kGA1sYxlcEPNAEcZsrMcCjwxgCPKXBF0Xx58DWVb8VBH2nJC--16nqAHyIFIS4OojDsZwwtpY6Gg8lzU7ALUpoYr3h6fKVMhZLm_w0EOCwRyzmDuPPIzy2YtyfQ"

	claims, _, err := parseJWT(jwtToken)
	if err != nil {
		log.Fatalf("JWT verification failed: %v", err)
	}

	// Print claims
	fmt.Printf("Verified JWT Claims:\n")
	fmt.Println(claims.Issuer, claims.Audience, claims.Subject)
}
