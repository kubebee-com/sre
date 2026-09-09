package cache

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

const encryptedVersion byte = 1

// Encryptor provides authenticated AES-GCM encryption for cache envelopes.
// The key is copied and never exposed after construction.
type Encryptor struct {
	aead cipher.AEAD
}

// NewEncryptor accepts an AES-sized key directly. Other non-empty key
// material is deterministically expanded to 32 bytes with SHA-256 so callers
// can supply a secret reference without weakening the AES-GCM boundary.
func NewEncryptor(key []byte) (*Encryptor, error) {
	if len(key) == 0 {
		return nil, ErrEncryptionKeyRequired
	}
	keyCopy := append([]byte(nil), key...)
	if len(keyCopy) != 16 && len(keyCopy) != 24 && len(keyCopy) != 32 {
		digest := sha256.Sum256(keyCopy)
		keyCopy = digest[:]
	}
	block, err := aes.NewCipher(keyCopy)
	if err != nil {
		return nil, errors.New("cache encryption cipher could not be initialized")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("cache encryption mode could not be initialized")
	}
	return &Encryptor{aead: aead}, nil
}

func (e *Encryptor) Seal(plaintext []byte) ([]byte, error) {
	if e == nil || e.aead == nil {
		return nil, ErrEncryptionKeyRequired
	}
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.New("cache encryption nonce could not be generated")
	}
	additionalData := []byte{encryptedVersion}
	ciphertext := e.aead.Seal(nil, nonce, plaintext, additionalData)
	result := make([]byte, 1+len(nonce)+len(ciphertext))
	result[0] = encryptedVersion
	copy(result[1:], nonce)
	copy(result[1+len(nonce):], ciphertext)
	return result, nil
}

func (e *Encryptor) Open(ciphertext []byte) ([]byte, error) {
	if e == nil || e.aead == nil {
		return nil, ErrEncryptionKeyRequired
	}
	nonceSize := e.aead.NonceSize()
	if len(ciphertext) <= 1+nonceSize || ciphertext[0] != encryptedVersion {
		return nil, ErrAuthentication
	}
	nonce := ciphertext[1 : 1+nonceSize]
	sealed := ciphertext[1+nonceSize:]
	plaintext, err := e.aead.Open(nil, nonce, sealed, []byte{encryptedVersion})
	if err != nil {
		return nil, ErrAuthentication
	}
	return plaintext, nil
}
