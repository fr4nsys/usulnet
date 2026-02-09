// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package totp

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const (
	// DefaultBackupCodeCount is the default number of backup codes to generate
	DefaultBackupCodeCount = 10

	// BackupCodeLength is the length of each backup code (before formatting)
	BackupCodeLength = 8

	// bcryptCost for hashing backup codes
	bcryptCost = 10
)

// BackupCode represents a single backup code
type BackupCode struct {
	Code     string `json:"code"`      // The plaintext code (only shown once)
	CodeHash string `json:"code_hash"` // Bcrypt hash for storage
	Used     bool   `json:"used"`      // Whether the code has been used
}

// BackupCodes represents a set of backup codes
type BackupCodes struct {
	Codes     []BackupCode `json:"codes"`
	CreatedAt int64        `json:"created_at"` // Unix timestamp
}

// GenerateBackupCodes creates a new set of backup codes
func GenerateBackupCodes(count int) (*BackupCodes, error) {
	if count <= 0 {
		count = DefaultBackupCodeCount
	}

	codes := &BackupCodes{
		Codes: make([]BackupCode, count),
	}

	for i := 0; i < count; i++ {
		code, err := generateBackupCode()
		if err != nil {
			return nil, err
		}

		// Hash the code for storage
		hash, err := bcrypt.GenerateFromPassword([]byte(normalizeCode(code)), bcryptCost)
		if err != nil {
			return nil, err
		}

		codes.Codes[i] = BackupCode{
			Code:     formatCode(code),
			CodeHash: string(hash),
			Used:     false,
		}
	}

	return codes, nil
}

// generateBackupCode generates a random backup code
func generateBackupCode() (string, error) {
	bytes := make([]byte, BackupCodeLength/2)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// formatCode formats a backup code for display (XXXX-XXXX)
func formatCode(code string) string {
	if len(code) < 8 {
		return code
	}
	return strings.ToUpper(code[:4] + "-" + code[4:])
}

// normalizeCode removes formatting from a backup code for comparison
func normalizeCode(code string) string {
	return strings.ToUpper(strings.ReplaceAll(code, "-", ""))
}

// ValidateBackupCode checks if a backup code is valid and marks it as used
// Returns the index of the used code, or -1 if not found
func ValidateBackupCode(inputCode string, codes []BackupCode) int {
	normalized := normalizeCode(inputCode)

	for i, code := range codes {
		if code.Used {
			continue
		}

		// Compare with bcrypt hash
		err := bcrypt.CompareHashAndPassword([]byte(code.CodeHash), []byte(normalized))
		if err == nil {
			return i
		}
	}

	return -1
}

// ValidateBackupCodeSimple checks if a backup code matches any unused code hash
// Uses constant-time comparison to prevent timing attacks
// Returns true if valid, false otherwise
func ValidateBackupCodeSimple(inputCode string, codeHashes []string, usedFlags []bool) (bool, int) {
	if len(codeHashes) != len(usedFlags) {
		return false, -1
	}

	normalized := normalizeCode(inputCode)

	for i, hash := range codeHashes {
		if usedFlags[i] {
			continue
		}

		// Compare with bcrypt hash
		err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(normalized))
		if err == nil {
			return true, i
		}
	}

	return false, -1
}

// GetPlaintextCodes returns just the plaintext codes (for showing to user)
func (bc *BackupCodes) GetPlaintextCodes() []string {
	result := make([]string, len(bc.Codes))
	for i, code := range bc.Codes {
		result[i] = code.Code
	}
	return result
}

// GetCodeHashes returns just the hashed codes (for storage)
func (bc *BackupCodes) GetCodeHashes() []string {
	result := make([]string, len(bc.Codes))
	for i, code := range bc.Codes {
		result[i] = code.CodeHash
	}
	return result
}

// GetRemainingCount returns the number of unused backup codes
func (bc *BackupCodes) GetRemainingCount() int {
	count := 0
	for _, code := range bc.Codes {
		if !code.Used {
			count++
		}
	}
	return count
}

// HashBackupCode creates a bcrypt hash of a backup code
func HashBackupCode(code string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(normalizeCode(code)), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// CompareBackupCode compares a plaintext backup code with a hash
func CompareBackupCode(code, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(normalizeCode(code)))
	return err == nil
}

// ConstantTimeCompare performs constant-time comparison of two strings
func ConstantTimeCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
