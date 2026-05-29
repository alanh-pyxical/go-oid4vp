// Package jose provides JWT construction and parsing helpers used internally
// by go-oid4vp. It mirrors the equivalent package in go-oid4vci but is kept
// separate so each module has zero cross-module internal dependencies.
package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

// Header is a JWT JOSE header represented as a loose map.
type Header map[string]any

// Claims is a JWT payload represented as a loose map.
type Claims map[string]any

// Signer produces raw signatures over JWT signing inputs.
type Signer interface {
	Sign(payload []byte) ([]byte, error)
	Algorithm() string
	KeyID() string
}

// Sign produces a compact-serialised JWT.
func Sign(typ string, extra Header, claims Claims, signer Signer) (string, error) {
	h := Header{"typ": typ, "alg": signer.Algorithm()}
	if kid := signer.KeyID(); kid != "" {
		h["kid"] = kid
	}
	for k, v := range extra {
		h[k] = v
	}

	hb, err := json.Marshal(h)
	if err != nil {
		return "", fmt.Errorf("jose: marshal header: %w", err)
	}
	pb, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("jose: marshal claims: %w", err)
	}

	he := base64.RawURLEncoding.EncodeToString(hb)
	pe := base64.RawURLEncoding.EncodeToString(pb)
	input := he + "." + pe

	sig, err := signer.Sign([]byte(input))
	if err != nil {
		return "", fmt.Errorf("jose: sign: %w", err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// Decode parses a compact JWT without verifying the signature.
func Decode(token string) (Header, Claims, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("jose: not a three-part JWT")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("jose: decode header: %w", err)
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("jose: decode payload: %w", err)
	}
	var h Header
	var c Claims
	if err := json.Unmarshal(hb, &h); err != nil {
		return nil, nil, fmt.Errorf("jose: parse header: %w", err)
	}
	if err := json.Unmarshal(pb, &c); err != nil {
		return nil, nil, fmt.Errorf("jose: parse claims: %w", err)
	}
	return h, c, nil
}

// Verify checks the signature of a compact JWT using pub and alg.
func Verify(token string, pub crypto.PublicKey, alg string) error {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return fmt.Errorf("jose: malformed token")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("jose: decode signature: %w", err)
	}
	digest, h, err := digestFor(alg, []byte(parts[0]+"."+parts[1]))
	if err != nil {
		return err
	}
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		return verifyEC(key, digest, sig)
	case *rsa.PublicKey:
		return verifyRSA(key, digest, sig, alg, h)
	default:
		return fmt.Errorf("jose: unsupported key type %T", pub)
	}
}

// PublicKeyToJWKMap serialises a public key to a JWK map.
func PublicKeyToJWKMap(pub crypto.PublicKey) (map[string]any, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		size := (k.Curve.Params().BitSize + 7) / 8
		xb := padLeft(k.X.Bytes(), size)
		yb := padLeft(k.Y.Bytes(), size)
		return map[string]any{
			"kty": "EC",
			"crv": k.Curve.Params().Name,
			"x":   base64.RawURLEncoding.EncodeToString(xb),
			"y":   base64.RawURLEncoding.EncodeToString(yb),
		}, nil
	case *rsa.PublicKey:
		return map[string]any{
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
		}, nil
	default:
		return nil, fmt.Errorf("jose: unsupported key type %T", pub)
	}
}

// JWKMapToPublicKey reconstructs a Go public key from a JWK map.
func JWKMapToPublicKey(m map[string]any) (crypto.PublicKey, error) {
	kty, _ := m["kty"].(string)
	switch kty {
	case "EC":
		return ecFromJWK(m)
	case "RSA":
		return rsaFromJWK(m)
	default:
		return nil, fmt.Errorf("jose: unsupported kty %q", kty)
	}
}

// ThumbprintSHA256 returns the base64url-encoded SHA-256 JWK thumbprint of pub.
func ThumbprintSHA256(pub crypto.PublicKey) (string, error) {
	m, err := PublicKeyToJWKMap(pub)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// ECDSASigner is a convenience Signer backed by *ecdsa.PrivateKey.
type ECDSASigner struct {
	Key *ecdsa.PrivateKey
	KID string
	Alg string
}

func (s *ECDSASigner) Sign(payload []byte) ([]byte, error) {
	digest, _, err := digestFor(s.Algorithm(), payload)
	if err != nil {
		return nil, err
	}
	r, sv, err := ecdsa.Sign(rand.Reader, s.Key, digest)
	if err != nil {
		return nil, err
	}
	size := (s.Key.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, 2*size)
	copy(sig[size-len(r.Bytes()):size], r.Bytes())
	copy(sig[2*size-len(sv.Bytes()):], sv.Bytes())
	return sig, nil
}

func (s *ECDSASigner) Algorithm() string {
	if s.Alg != "" {
		return s.Alg
	}
	switch s.Key.Curve.Params().Name {
	case "P-384":
		return "ES384"
	case "P-521":
		return "ES512"
	default:
		return "ES256"
	}
}

func (s *ECDSASigner) KeyID() string { return s.KID }

func (s *ECDSASigner) PublicKeyJWK() (map[string]any, error) {
	return PublicKeyToJWKMap(&s.Key.PublicKey)
}

// --- internal helpers ---

func digestFor(alg string, data []byte) ([]byte, crypto.Hash, error) {
	switch alg {
	case "ES256", "RS256", "PS256":
		d := sha256.Sum256(data)
		return d[:], crypto.SHA256, nil
	case "ES384", "RS384", "PS384":
		d := sha512.Sum384(data)
		return d[:], crypto.SHA384, nil
	case "ES512", "RS512", "PS512":
		d := sha512.Sum512(data)
		return d[:], crypto.SHA512, nil
	default:
		return nil, 0, fmt.Errorf("jose: unsupported algorithm %q", alg)
	}
}

func verifyEC(key *ecdsa.PublicKey, digest, sig []byte) error {
	l := len(sig) / 2
	r := new(big.Int).SetBytes(sig[:l])
	s := new(big.Int).SetBytes(sig[l:])
	if !ecdsa.Verify(key, digest, r, s) {
		return fmt.Errorf("jose: ECDSA signature invalid")
	}
	return nil
}

func verifyRSA(key *rsa.PublicKey, digest, sig []byte, alg string, h crypto.Hash) error {
	if strings.HasPrefix(alg, "PS") {
		return rsa.VerifyPSS(key, h, digest, sig, nil)
	}
	return rsa.VerifyPKCS1v15(key, h, digest, sig)
}

func ecFromJWK(m map[string]any) (*ecdsa.PublicKey, error) {
	crv, _ := m["crv"].(string)
	xb, err := b64Decode(m, "x")
	if err != nil {
		return nil, fmt.Errorf("jose: EC JWK x: %w", err)
	}
	yb, err := b64Decode(m, "y")
	if err != nil {
		return nil, fmt.Errorf("jose: EC JWK y: %w", err)
	}
	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("jose: unsupported EC curve %q", crv)
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xb),
		Y:     new(big.Int).SetBytes(yb),
	}, nil
}

func rsaFromJWK(m map[string]any) (*rsa.PublicKey, error) {
	nb, err := b64Decode(m, "n")
	if err != nil {
		return nil, fmt.Errorf("jose: RSA JWK n: %w", err)
	}
	eb, err := b64Decode(m, "e")
	if err != nil {
		return nil, fmt.Errorf("jose: RSA JWK e: %w", err)
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nb),
		E: int(new(big.Int).SetBytes(eb).Int64()),
	}, nil
}

func b64Decode(m map[string]any, key string) ([]byte, error) {
	s, ok := m[key].(string)
	if !ok {
		return nil, fmt.Errorf("field %q missing or not a string", key)
	}
	return base64.RawURLEncoding.DecodeString(s)
}

func padLeft(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
