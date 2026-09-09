package cache

import (
	"bytes"
	"errors"
	"testing"
)

func TestEncryptorUsesAuthenticatedEncryption(t *testing.T) {
	encryptor, err := NewEncryptor([]byte("cache-encryption-key"))
	if err != nil {
		t.Fatalf("NewEncryptor() error = %v", err)
	}
	plaintext := []byte("provider response with sensitive context")
	ciphertext, err := encryptor.Seal(plaintext)
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if bytes.Contains(ciphertext, plaintext) {
		t.Fatal("ciphertext contains plaintext")
	}
	opened, err := encryptor.Open(ciphertext)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("Open() = %q, %v; want plaintext", opened, err)
	}

	ciphertext[len(ciphertext)-1] ^= 1
	if _, err := encryptor.Open(ciphertext); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tampered Open() error = %v, want ErrAuthentication", err)
	}
}
