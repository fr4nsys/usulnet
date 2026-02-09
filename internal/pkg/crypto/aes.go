// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
)

// Errors
var (
	ErrInvalidKey        = errors.New("invalid encryption key: must be 32 bytes hex-encoded")
	ErrInvalidCiphertext = errors.New("invalid ciphertext")
	ErrDecryptionFailed  = errors.New("decryption failed: authentication failed")
)

// AESEncryptor provides AES-256-GCM encryption/decryption
type AESEncryptor struct {
	key []byte
	gcm cipher.AEAD
}

// Encryptor is an alias for AESEncryptor for backward compatibility
type Encryptor = AESEncryptor

// NewEncryptor creates a new encryptor from a hex-encoded key
// This is an alias for NewAESEncryptor for backward compatibility
func NewEncryptor(keyHex string) (*Encryptor, error) {
	return NewAESEncryptor(keyHex)
}

// NewAESEncryptor creates a new AES encryptor from a hex-encoded key
func NewAESEncryptor(keyHex string) (*AESEncryptor, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, ErrInvalidKey
	}
	if len(key) != 32 { // AES-256 requires 32-byte key
		return nil, ErrInvalidKey
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &AESEncryptor{
		key: key,
		gcm: gcm,
	}, nil
}

// NewAESEncryptorFromBytes creates a new AES encryptor from raw bytes
func NewAESEncryptorFromBytes(key []byte) (*AESEncryptor, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKey
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &AESEncryptor{
		key: key,
		gcm: gcm,
	}, nil
}

// Encrypt encrypts plaintext and returns base64-encoded ciphertext
func (e *AESEncryptor) Encrypt(plaintext []byte) (string, error) {
	// Generate random nonce
	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Encrypt and append nonce to beginning of ciphertext
	ciphertext := e.gcm.Seal(nonce, nonce, plaintext, nil)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts base64-encoded ciphertext and returns plaintext
func (e *AESEncryptor) Decrypt(ciphertextB64 string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, ErrInvalidCiphertext
	}

	nonceSize := e.gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrInvalidCiphertext
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := e.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// EncryptString encrypts a string and returns base64-encoded ciphertext
func (e *AESEncryptor) EncryptString(plaintext string) (string, error) {
	return e.Encrypt([]byte(plaintext))
}

// DecryptString decrypts base64-encoded ciphertext and returns plaintext string
func (e *AESEncryptor) DecryptString(ciphertext string) (string, error) {
	plaintext, err := e.Decrypt(ciphertext)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// EncryptToHex encrypts plaintext and returns hex-encoded ciphertext
func (e *AESEncryptor) EncryptToHex(plaintext []byte) (string, error) {
	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := e.gcm.Seal(nonce, nonce, plaintext, nil)
	return hex.EncodeToString(ciphertext), nil
}

// DecryptFromHex decrypts hex-encoded ciphertext and returns plaintext
func (e *AESEncryptor) DecryptFromHex(ciphertextHex string) ([]byte, error) {
	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return nil, ErrInvalidCiphertext
	}

	nonceSize := e.gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrInvalidCiphertext
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := e.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// GenerateKey generates a new random 32-byte key and returns it hex-encoded
func GenerateKey() (string, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

// ValidateKey checks if a key is valid for AES-256
func ValidateKey(keyHex string) error {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return ErrInvalidKey
	}
	if len(key) != 32 {
		return ErrInvalidKey
	}
	return nil
}
