package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateKeyRejectsShortFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.key")
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKey(path); err == nil {
		t.Fatal("a truncated key file was silently replaced")
	}
}

func TestRoundtrip(t *testing.T) {
	key := make([]byte, KeyLen)
	for i := range key {
		key[i] = byte(i)
	}
	plain := "Sup3rSecret!密码"
	enc, err := Encrypt(plain, key)
	if err != nil {
		t.Fatal(err)
	}
	if enc == plain || enc == "" {
		t.Fatal("plaintext was not encrypted")
	}
	got, err := Decrypt(enc, key)
	if err != nil {
		t.Fatal(err)
	}
	if got != plain {
		t.Fatalf("roundtrip mismatch: %q != %q", got, plain)
	}
}

func TestWrongKey(t *testing.T) {
	key1 := make([]byte, KeyLen)
	key2 := make([]byte, KeyLen)
	key2[0] = 1
	enc, _ := Encrypt("secret", key1)
	if _, err := Decrypt(enc, key2); err == nil {
		t.Fatal("expected decrypt failure with wrong key")
	}
}

func TestEmpty(t *testing.T) {
	key := make([]byte, KeyLen)
	if enc, _ := Encrypt("", key); enc != "" {
		t.Fatal("empty plaintext should stay empty")
	}
	if got, _ := Decrypt("", key); got != "" {
		t.Fatal("empty ciphertext should decrypt to empty")
	}
}
