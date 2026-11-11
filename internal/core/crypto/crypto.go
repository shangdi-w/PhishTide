// Package crypto provides AES-256-GCM encryption for sensitive at-rest data
// (SMTP credentials). The master key is either supplied via PHISH_SECRET_KEY
// (64 hex chars) or generated and persisted to a local key file.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
)

// KeyLen is the AES-256 key length in bytes.
const KeyLen = 32

// KeyFromHex decodes a 64-char hex string into a 32-byte key.
func KeyFromHex(s string) ([]byte, error) {
	if len(s) != KeyLen*2 {
		return nil, fmt.Errorf("secret key must be %d hex chars", KeyLen*2)
	}
	key, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(key) != KeyLen {
		return nil, errors.New("bad key length")
	}
	return key, nil
}

// LoadOrCreateKey returns a 32-byte key, reading it from path when present or
// generating and persisting a fresh one otherwise.
func LoadOrCreateKey(path string) ([]byte, error) {
	if data, err := os.ReadFile(path); err == nil {
		if len(data) < KeyLen {
			return nil, fmt.Errorf("secret key file %s is too short (%d bytes)", path, len(data))
		}
		return data[:KeyLen], nil
	}
	key := make([]byte, KeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// Encrypt seals plaintext with AES-256-GCM and returns base64(nonce|ciphertext).
func Encrypt(plain string, key []byte) (string, error) {
	if plain == "" {
		return "", nil
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
	ct := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

// Decrypt reverses Encrypt. An empty input yields an empty output.
func Decrypt(enc string, key []byte) (string, error) {
	if enc == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}
	return string(plain), nil
}

// EncryptBytes seals arbitrary bytes with AES-256-GCM. The output layout is
// nonce|ciphertext, matching Encrypt's string form without base64.
func EncryptBytes(plain, key []byte) ([]byte, error) {
	if len(plain) == 0 {
		return []byte{}, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, nil), nil
}

// DecryptBytes reverses EncryptBytes.
func DecryptBytes(sealed, key []byte) ([]byte, error) {
	if len(sealed) == 0 {
		return []byte{}, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plain, nil
}
