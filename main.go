package main

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/pelletier/go-toml/v2"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/golang-jwt/jwt/v4"
)

// generateShares does standard Shamir in BN254 with polynomial degree T-1
// x=1..N. Returns arrays of length N for xCoords and yCoords.
func generateShares(secret fr.Element, T, N int) ([]fr.Element, []fr.Element, error) {
	if T < 2 || N < T {
		return nil, nil, fmt.Errorf("invalid T=%d, N=%d", T, N)
	}
	// polynomial coefs of length T => degree T-1
	coefs := make([]fr.Element, T)
	coefs[0].Set(&secret)
	for i := 1; i < T; i++ {
		var r fr.Element
		r.SetRandom()
		coefs[i].Set(&r)
	}

	xCoords := make([]fr.Element, N)
	yCoords := make([]fr.Element, N)
	for i := 0; i < N; i++ {
		xCoords[i].SetUint64(uint64(i + 1))
		yCoords[i] = polyEval(coefs, xCoords[i])
	}
	return xCoords, yCoords, nil
}

func polyEval(coefs []fr.Element, x fr.Element) fr.Element {
	var res, tmp, xPow fr.Element
	res.SetZero()
	xPow.SetOne()
	for _, c := range coefs {
		tmp.Mul(&c, &xPow)
		res.Add(&res, &tmp)
		xPow.Mul(&xPow, &x)
	}
	return res
}

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

// Data holds a padded byte array (represented as a slice of ints)
// and the original length.
type Data struct {
	Storage []int `json:"storage"`
	Len     int   `json:"len"`
}

// JWTCircuitInputs holds all the fields required by the circuit.
type JWTCircuitInputs struct {
	Data               *Data    `json:"data,omitempty"`
	Base64DecodeOffset int      `json:"base64_decode_offset"`
	PubkeyModulusLimbs []string `json:"pubkey_modulus_limbs"`
	RedcParamsLimbs    []string `json:"redc_params_limbs"`
	SignatureLimbs     []string `json:"signature_limbs"`
	PartialData        *Data    `json:"partial_data,omitempty"`
	PartialHash        []int    `json:"partial_hash,omitempty"`
	FullDataLength     int      `json:"full_data_length,omitempty"`
}

// GenerateInputsParams defines the parameters required to generate inputs.
type GenerateInputsParams struct {
	JWT                   string
	Pubkey                *rsa.PublicKey
	ShaPrecomputeTillKeys []string
	MaxSignedDataLength   int
}

// generateInputs processes the JWT and public key to create circuit inputs.
func generateInputs(params GenerateInputsParams) (JWTCircuitInputs, error) {
	jwt := params.JWT
	pubkey := params.Pubkey
	shaPrecomputeTillKeys := params.ShaPrecomputeTillKeys
	maxSignedDataLength := params.MaxSignedDataLength

	parts := strings.Split(jwt, ".")
	if len(parts) < 3 {
		return JWTCircuitInputs{}, errors.New("invalid jwt token: not enough parts")
	}
	headerB64 := parts[0]
	payloadB64 := parts[1]
	signatureB64Url := parts[2]

	// Concatenate header and payload (as in "$header.$payload")
	signedDataString := headerB64 + "." + payloadB64
	signedData := []byte(signedDataString)

	// Decode the signature (Base64Url decoding)
	signatureBytes, err := base64UrlDecode(signatureB64Url)
	if err != nil {
		return JWTCircuitInputs{}, fmt.Errorf("failed to decode signature: %v", err)
	}
	// Convert the signature bytes into a big.Int.
	signatureBigInt := new(big.Int).SetBytes(signatureBytes)

	pubkeyBigInt := pubkey.N

	// Compute redcParam = (1 << 4100) / pubkeyBigInt.
	// (Note: 2*2048 + 4 = 4100)
	redcParam := new(big.Int).Lsh(big.NewInt(1), 4100)
	redcParam.Div(redcParam, pubkeyBigInt)

	// Split big integers into fixed-size chunks.
	pubkeyLimbs := splitBigIntToChunks(pubkeyBigInt, 120, 18)
	redcParamsLimbs := splitBigIntToChunks(redcParam, 120, 18)
	signatureLimbs := splitBigIntToChunks(signatureBigInt, 120, 18)

	// Convert the big.Int limbs to strings.
	pubkeyLimbsStr := make([]string, len(pubkeyLimbs))
	for i, limb := range pubkeyLimbs {
		pubkeyLimbsStr[i] = limb.String()
	}
	redcParamsLimbsStr := make([]string, len(redcParamsLimbs))
	for i, limb := range redcParamsLimbs {
		redcParamsLimbsStr[i] = limb.String()
	}
	signatureLimbsStr := make([]string, len(signatureLimbs))
	for i, limb := range signatureLimbs {
		signatureLimbsStr[i] = limb.String()
	}

	inputs := JWTCircuitInputs{
		PubkeyModulusLimbs: pubkeyLimbsStr,
		RedcParamsLimbs:    redcParamsLimbsStr,
		SignatureLimbs:     signatureLimbsStr,
	}

	// If no SHA precompute keys are provided, use the full signed data.
	if len(shaPrecomputeTillKeys) == 0 {
		if len(signedData) > maxSignedDataLength {
			return JWTCircuitInputs{}, errors.New("signed data length exceeds maxSignedDataLength")
		}
		// Pad signedData to the maximum allowed length.
		signedDataPadded := make([]byte, maxSignedDataLength)
		copy(signedDataPadded, signedData)
		inputs.Data = &Data{
			Storage: byteSliceToIntSlice(signedDataPadded),
			Len:     len(signedData),
		}
		// The decode offset is set to the index after the header plus the dot.
		inputs.Base64DecodeOffset = len(headerB64) + 1
	} else {
		// Precompute SHA256 on a portion of signedData.
		// Decode the payload to a string.
		payloadBytes, err := base64UrlDecode(payloadB64)
		if err != nil {
			return JWTCircuitInputs{}, fmt.Errorf("failed to decode payload: %v", err)
		}
		payloadString := string(payloadBytes)

		// Find the first occurrence among all keys.
		smallestIndex := -1
		for _, key := range shaPrecomputeTillKeys {
			searchStr := fmt.Sprintf(`"%s":`, key)
			idx := strings.Index(payloadString, searchStr)
			if idx != -1 {
				if smallestIndex == -1 || idx < smallestIndex {
					smallestIndex = idx
				}
			}
		}
		if smallestIndex == -1 {
			return JWTCircuitInputs{}, errors.New("none of the precompute keys found in payload")
		}
		// Compute the corresponding index in the Base64 string.
		smallerIndexInB64 := (smallestIndex * 4) / 3
		sliceStart := len(headerB64) + smallerIndexInB64 + 1

		// Generate partial SHA256.
		partialHash, remainingData, err := generatePartialSHA256(signedData, sliceStart)
		if err != nil {
			return JWTCircuitInputs{}, fmt.Errorf("failed to generate partial SHA256: %v", err)
		}
		if len(remainingData) > maxSignedDataLength {
			return JWTCircuitInputs{}, errors.New("remainingData after partial hash exceeds maxSignedDataLength")
		}
		remainingDataPadded := make([]byte, maxSignedDataLength)
		copy(remainingDataPadded, remainingData)

		inputs.PartialData = &Data{
			Storage: byteSliceToIntSlice(remainingDataPadded),
			Len:     len(remainingData),
		}
		inputs.PartialHash = byteSliceToIntSlice(partialHash)
		inputs.FullDataLength = len(signedData)

		// Calculate the offset to ensure the remaining payload is a multiple of 4.
		shaCutoffIndex := len(signedData) - len(remainingData)
		payloadBytesInShaPrecompute := shaCutoffIndex - (len(headerB64) + 1)
		offsetToMakeIt4x := 4 - (payloadBytesInShaPrecompute % 4)
		inputs.Base64DecodeOffset = offsetToMakeIt4x
	}

	return inputs, nil
}

// splitBigIntToChunks splits a big.Int into fixed-size chunks.
// Each chunk is of size 'chunkSize' (in bits) and we return 'numChunks' of them.
func splitBigIntToChunks(bigInt *big.Int, chunkSize int, numChunks int) []*big.Int {
	chunks := make([]*big.Int, numChunks)
	// mask = (1 << chunkSize) - 1
	mask := new(big.Int).Lsh(big.NewInt(1), uint(chunkSize))
	mask.Sub(mask, big.NewInt(1))
	for i := 0; i < numChunks; i++ {
		// shifted = bigInt >> (i * chunkSize)
		shifted := new(big.Int).Rsh(bigInt, uint(i*chunkSize))
		// chunk = shifted & mask
		chunk := new(big.Int).And(shifted, mask)
		chunks[i] = chunk
	}
	return chunks
}

// generatePartialSHA256 precomputes SHA256 on a prefix of the data.
// It computes the SHA256 hash on the largest multiple of 64 bytes
// that is less than or equal to sliceStart. The function returns the hash
// and the remaining data.
func generatePartialSHA256(data []byte, sliceStart int) ([]byte, []byte, error) {
	// Find the largest multiple of 64 that is <= sliceStart.
	boundary := (sliceStart / 64) * 64
	if boundary > len(data) {
		boundary = len(data)
	}
	hash := sha256.Sum256(data[:boundary])
	remainingData := data[boundary:]
	return hash[:], remainingData, nil
}

// base64UrlDecode decodes a Base64Url-encoded string.
// It replaces URL-specific characters and adds padding if necessary.
func base64UrlDecode(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	// Add padding if necessary.
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	case 1:
		return nil, errors.New("invalid base64 string")
	}
	return base64.StdEncoding.DecodeString(s)
}

// byteSliceToIntSlice converts a byte slice into a slice of ints.
func byteSliceToIntSlice(b []byte) []int {
	res := make([]int, len(b))
	for i, v := range b {
		res[i] = int(v)
	}
	return res
}

type BoundedVec struct {
	Storage []int `toml:"storage"`
	Len     int   `toml:"len"`
}

type noirInput struct {
	XCoords        []string   `toml:"x_coords"`
	YCoords        []string   `toml:"y_coords"`
	Share          [2]string  `toml:"share"`
	Data           BoundedVec `toml:"data"`
	Base64Offset   int        `toml:"b64_offset"`
	PubkeyModulus  []string   `toml:"pubkey_modulus_limbs"`
	RedcParams     []string   `toml:"redc_params_limbs"`
	SignatureLimbs []string   `toml:"signature_limbs"`
	Domain         BoundedVec `toml:"domain"`
	Issuer         BoundedVec `toml:"issuer"`
	CurrentTime    int64      `toml:"current_time"`
}

func writeProofInputsTOML(xArr, yArr []string, secret string, input JWTCircuitInputs, claims *GoogleClaims, filename string) error {
	// Create the ProofInputs struct
	paddedDomain := make([]byte, 100)
	unpaddedDomain := []byte(claims.Audience[0])
	copy(paddedDomain, []byte(unpaddedDomain))
	domain := byteSliceToIntSlice(paddedDomain)

	paddedIssuer := make([]byte, 100)
	unPaddedIssuer := []byte(claims.Issuer)
	copy(paddedIssuer, unPaddedIssuer)
	issuer := byteSliceToIntSlice(paddedIssuer)

	inputs := noirInput{
		XCoords: xArr,
		YCoords: yArr,
		Share:   [2]string{xArr[0], yArr[0]},
		Data: BoundedVec{
			Storage: input.Data.Storage,
			Len:     input.Data.Len,
		},
		Base64Offset:   input.Base64DecodeOffset,
		PubkeyModulus:  input.PubkeyModulusLimbs,
		RedcParams:     input.RedcParamsLimbs,
		SignatureLimbs: input.SignatureLimbs,
		Domain: BoundedVec{
			Storage: domain,
			Len:     len(unpaddedDomain),
		},
		Issuer: BoundedVec{
			Storage: issuer,
			Len:     len(unPaddedIssuer),
		},
		CurrentTime: time.Now().Unix(),
	}

	// Encode to TOML
	tomlData, err := toml.Marshal(inputs)
	if err != nil {
		return fmt.Errorf("failed to encode TOML: %w", err)
	}

	// Write to file
	err = os.WriteFile(filename, tomlData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write TOML file: %w", err)
	}

	return nil
}

func main() {
	jwtToken := "eyJhbGciOiJSUzI1NiIsImtpZCI6IjI1ZjgyMTE3MTM3ODhiNjE0NTQ3NGI1MDI5YjAxNDFiZDViM2RlOWMiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI4MjUyOTU1NTY0MDAtNmhjdmgzb2Qwcm04NnZrOGFsZGVqZmpxaWJkaWxkZmUuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI4MjUyOTU1NTY0MDAtNmhjdmgzb2Qwcm04NnZrOGFsZGVqZmpxaWJkaWxkZmUuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDA3MDM2NzgwMzY2NDg5OTIxMjYiLCJlbWFpbCI6InNvZWRlcmJveUBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfaGFzaCI6IkV2TVVHMFNDQlpJR1RvRzFpZVFJVkEiLCJuYW1lIjoiS2kgQWdlbmcgU2F0cmlhIFBhbXVuZ2thcyIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQ2c4b2NLSjE1anhMdkhHTUh1YWNNLXFLcU5BcnlqQ3pwY2c2UjlHa25wdWZUOU5qaGxJSkJfcD1zOTYtYyIsImdpdmVuX25hbWUiOiJLaSBBZ2VuZyBTYXRyaWEiLCJmYW1pbHlfbmFtZSI6IlBhbXVuZ2thcyIsImlhdCI6MTc0MTM2MTkwMywiZXhwIjoxNzQxMzY1NTAzfQ.y4V8sV75vZPDJGRh-mdnqqhGOoEcwAXSqDjSSk68Z51VW_aOhbsh2TRIV5tPQk_wd5sjtbKjWAtKXrgZ0uhpsoXEjURf3HzUpvb-6vAWeLVTAta0DVKdSpNRCMcdSIy1JTRXghc2-PTF3-DNph9ipzcDhHIhK4lhedByPQ2ldgT83P-7lfFsiqNmJl0KiZovK-fj_DlmGM5Hd_DDkIFGdti1rtylbuI_QD3N6jVDklERxREQpf9G6wFghtlipZjOxZcZJKE_U_op5yUfHTV3nejeYsAbmvPudOveLtfTQ57r3OAAdNaZwbm-p1wjnrpP8y8YjyTNEeP26TBiyNNJMg"

	claims, pubKey, err := parseJWT(jwtToken)
	if err != nil {
		log.Fatalf("JWT verification failed: %v", err)
	}

	input, err := generateInputs(GenerateInputsParams{
		JWT:                   jwtToken,
		Pubkey:                pubKey,
		ShaPrecomputeTillKeys: nil,
		MaxSignedDataLength:   900,
	})
	if err != nil {
		log.Fatalf("JWT input failed: %v", err)
	}

	T := 3
	N := 5

	var secret fr.Element
	secret.SetBytes([]byte(claims.Subject))
	var falseSecret fr.Element
	falseSecret.SetBytes([]byte("tob tob tob"))

	xCoords, yCoords, err := generateShares(secret, T, N)
	if err != nil {
		log.Fatal(err)
	}

	chosenX := make([]string, T)
	chosenY := make([]string, T)
	for i := 0; i < T; i++ {
		chosenX[i] = xCoords[i].String()
		chosenY[i] = yCoords[i].String()
	}

	err = writeProofInputsTOML(chosenX, chosenY, secret.String(), input, claims, "proof_inputs.toml")
	if err != nil {
		log.Fatalf("failed to write proof_inputs.toml: %v", err)
	}

	start := time.Now()
	cmd := exec.Command("nargo", "execute", "--program-dir", "./zk/syra_login",
		"-p", "../../proof_inputs")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("nargo prove failed: %v\nOutput:\n%s", err, string(out))
	}

	latency := time.Since(start)
	fmt.Printf("Nargo execution time: %v\n", latency)

	start = time.Now()

	cmdbb := exec.Command("bb", "prove", "-b", "./zk/syra_login/target/syra_login.json",
		"-w", "./zk/syra_login/target/syra_login.gz",
		"-o", "./zk/syra_login/target/proof")
	outbb, err := cmdbb.CombinedOutput()
	if err != nil {
		log.Fatalf("bb prove failed: %v\nOutput:\n%s", err, string(outbb))
	}

	latency = time.Since(start)
	fmt.Printf("bb execution time: %v\n", latency)
}
