// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package crypto

import (
	"strings"
	"unicode"
)

// PasswordPolicy defines password requirements
type PasswordPolicy struct {
	// MinLength is the minimum password length (default: 8)
	MinLength int

	// MaxLength is the maximum password length (default: 128)
	MaxLength int

	// RequireUppercase requires at least one uppercase letter
	RequireUppercase bool

	// RequireLowercase requires at least one lowercase letter
	RequireLowercase bool

	// RequireNumber requires at least one digit
	RequireNumber bool

	// RequireSpecial requires at least one special character
	RequireSpecial bool

	// MinUppercase is the minimum number of uppercase letters (default: 1 if RequireUppercase)
	MinUppercase int

	// MinLowercase is the minimum number of lowercase letters (default: 1 if RequireLowercase)
	MinLowercase int

	// MinNumbers is the minimum number of digits (default: 1 if RequireNumber)
	MinNumbers int

	// MinSpecial is the minimum number of special characters (default: 1 if RequireSpecial)
	MinSpecial int

	// DisallowUsername prevents password from containing the username
	DisallowUsername bool

	// DisallowCommonPasswords checks against a list of common passwords
	DisallowCommonPasswords bool

	// MaxConsecutiveChars is the maximum number of consecutive identical characters (0 = no limit)
	MaxConsecutiveChars int
}

// DefaultPasswordPolicy returns a sensible default password policy
func DefaultPasswordPolicy() PasswordPolicy {
	return PasswordPolicy{
		MinLength:               8,
		MaxLength:               128,
		RequireUppercase:        true,
		RequireLowercase:        true,
		RequireNumber:           true,
		RequireSpecial:          false, // Not required by default
		MinUppercase:            1,
		MinLowercase:            1,
		MinNumbers:              1,
		MinSpecial:              0,
		DisallowUsername:        true,
		DisallowCommonPasswords: true,
		MaxConsecutiveChars:     3,
	}
}

// StrictPasswordPolicy returns a stricter password policy
func StrictPasswordPolicy() PasswordPolicy {
	return PasswordPolicy{
		MinLength:               12,
		MaxLength:               128,
		RequireUppercase:        true,
		RequireLowercase:        true,
		RequireNumber:           true,
		RequireSpecial:          true,
		MinUppercase:            1,
		MinLowercase:            1,
		MinNumbers:              1,
		MinSpecial:              1,
		DisallowUsername:        true,
		DisallowCommonPasswords: true,
		MaxConsecutiveChars:     3,
	}
}

// MinimalPasswordPolicy returns a minimal password policy (just length)
func MinimalPasswordPolicy() PasswordPolicy {
	return PasswordPolicy{
		MinLength:               8,
		MaxLength:               128,
		RequireUppercase:        false,
		RequireLowercase:        false,
		RequireNumber:           false,
		RequireSpecial:          false,
		DisallowUsername:        false,
		DisallowCommonPasswords: false,
		MaxConsecutiveChars:     0,
	}
}

// PasswordValidationResult contains the result of password validation
type PasswordValidationResult struct {
	Valid    bool     `json:"valid"`
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
	Score    int      `json:"score"` // 0-100 strength score
}

// ValidatePassword validates a password against the policy
func (p PasswordPolicy) ValidatePassword(password string, username string) PasswordValidationResult {
	result := PasswordValidationResult{
		Valid:  true,
		Errors: []string{},
		Score:  0,
	}

	// Length checks
	if len(password) < p.MinLength {
		result.Valid = false
		result.Errors = append(result.Errors, "Password must be at least "+itoa(p.MinLength)+" characters")
	} else {
		result.Score += 20
	}

	if len(password) > p.MaxLength {
		result.Valid = false
		result.Errors = append(result.Errors, "Password must be at most "+itoa(p.MaxLength)+" characters")
	}

	// Character type counts
	var upperCount, lowerCount, numberCount, specialCount int
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			upperCount++
		case unicode.IsLower(r):
			lowerCount++
		case unicode.IsDigit(r):
			numberCount++
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			specialCount++
		}
	}

	// Uppercase check
	if p.RequireUppercase && upperCount < p.MinUppercase {
		result.Valid = false
		if p.MinUppercase == 1 {
			result.Errors = append(result.Errors, "Password must contain at least one uppercase letter")
		} else {
			result.Errors = append(result.Errors, "Password must contain at least "+itoa(p.MinUppercase)+" uppercase letters")
		}
	} else if upperCount > 0 {
		result.Score += 15
	}

	// Lowercase check
	if p.RequireLowercase && lowerCount < p.MinLowercase {
		result.Valid = false
		if p.MinLowercase == 1 {
			result.Errors = append(result.Errors, "Password must contain at least one lowercase letter")
		} else {
			result.Errors = append(result.Errors, "Password must contain at least "+itoa(p.MinLowercase)+" lowercase letters")
		}
	} else if lowerCount > 0 {
		result.Score += 15
	}

	// Number check
	if p.RequireNumber && numberCount < p.MinNumbers {
		result.Valid = false
		if p.MinNumbers == 1 {
			result.Errors = append(result.Errors, "Password must contain at least one number")
		} else {
			result.Errors = append(result.Errors, "Password must contain at least "+itoa(p.MinNumbers)+" numbers")
		}
	} else if numberCount > 0 {
		result.Score += 15
	}

	// Special character check
	if p.RequireSpecial && specialCount < p.MinSpecial {
		result.Valid = false
		if p.MinSpecial == 1 {
			result.Errors = append(result.Errors, "Password must contain at least one special character")
		} else {
			result.Errors = append(result.Errors, "Password must contain at least "+itoa(p.MinSpecial)+" special characters")
		}
	} else if specialCount > 0 {
		result.Score += 15
	}

	// Username check
	if p.DisallowUsername && username != "" {
		if strings.Contains(strings.ToLower(password), strings.ToLower(username)) {
			result.Valid = false
			result.Errors = append(result.Errors, "Password must not contain your username")
		}
	}

	// Consecutive characters check
	if p.MaxConsecutiveChars > 0 {
		consecutive := checkConsecutive(password, p.MaxConsecutiveChars)
		if consecutive {
			result.Valid = false
			result.Errors = append(result.Errors, "Password must not contain more than "+itoa(p.MaxConsecutiveChars)+" consecutive identical characters")
		}
	}

	// Common passwords check
	if p.DisallowCommonPasswords {
		if isCommonPassword(strings.ToLower(password)) {
			result.Valid = false
			result.Errors = append(result.Errors, "Password is too common and easily guessable")
		}
	}

	// Bonus points for length
	if len(password) >= 12 {
		result.Score += 10
	}
	if len(password) >= 16 {
		result.Score += 10
	}

	// Cap score at 100
	if result.Score > 100 {
		result.Score = 100
	}

	// Add warnings for weak patterns (but don't fail validation)
	if result.Valid && result.Score < 50 {
		result.Warnings = append(result.Warnings, "Consider using a stronger password")
	}

	return result
}

// checkConsecutive checks if password has more than maxConsec consecutive identical characters
func checkConsecutive(password string, maxConsec int) bool {
	if maxConsec <= 0 {
		return false
	}

	runes := []rune(password)
	count := 1

	for i := 1; i < len(runes); i++ {
		if runes[i] == runes[i-1] {
			count++
			if count > maxConsec {
				return true
			}
		} else {
			count = 1
		}
	}

	return false
}

// isCommonPassword checks if the password is in the common passwords list
func isCommonPassword(password string) bool {
	// Top 100 most common passwords
	commonPasswords := map[string]bool{
		"123456":      true,
		"password":    true,
		"12345678":    true,
		"qwerty":      true,
		"123456789":   true,
		"12345":       true,
		"1234":        true,
		"111111":      true,
		"1234567":     true,
		"dragon":      true,
		"123123":      true,
		"baseball":    true,
		"abc123":      true,
		"football":    true,
		"monkey":      true,
		"letmein":     true,
		"696969":      true,
		"shadow":      true,
		"master":      true,
		"666666":      true,
		"qwertyuiop":  true,
		"123321":      true,
		"mustang":     true,
		"1234567890":  true,
		"michael":     true,
		"654321":      true,
		"pussy":       true,
		"superman":    true,
		"1qaz2wsx":    true,
		"7777777":     true,
		"fuckyou":     true,
		"121212":      true,
		"000000":      true,
		"qazwsx":      true,
		"123qwe":      true,
		"killer":      true,
		"trustno1":    true,
		"jordan":      true,
		"jennifer":    true,
		"zxcvbnm":     true,
		"asdfgh":      true,
		"hunter":      true,
		"buster":      true,
		"soccer":      true,
		"harley":      true,
		"batman":      true,
		"andrew":      true,
		"tigger":      true,
		"sunshine":    true,
		"iloveyou":    true,
		"fuckme":      true,
		"2000":        true,
		"charlie":     true,
		"robert":      true,
		"thomas":      true,
		"hockey":      true,
		"ranger":      true,
		"daniel":      true,
		"starwars":    true,
		"klaster":     true,
		"112233":      true,
		"george":      true,
		"asshole":     true,
		"computer":    true,
		"michelle":    true,
		"jessica":     true,
		"pepper":      true,
		"1111":        true,
		"zxcvbn":      true,
		"555555":      true,
		"11111111":    true,
		"131313":      true,
		"freedom":     true,
		"777777":      true,
		"pass":        true,
		"fuck":        true,
		"maggie":      true,
		"159753":      true,
		"aaaaaa":      true,
		"ginger":      true,
		"princess":    true,
		"joshua":      true,
		"cheese":      true,
		"amanda":      true,
		"summer":      true,
		"love":        true,
		"ashley":      true,
		"6969":        true,
		"nicole":      true,
		"chelsea":     true,
		"biteme":      true,
		"matthew":     true,
		"access":      true,
		"yankees":     true,
		"987654321":   true,
		"dallas":      true,
		"austin":      true,
		"thunder":     true,
		"taylor":      true,
		"matrix":      true,
		"password1":   true,
		"password123": true,
		"admin":       true,
		"admin123":    true,
		"root":        true,
		"toor":        true,
		"pass123":     true,
		"test":        true,
		"test123":     true,
		"guest":       true,
		"master123":   true,
		"changeme":    true,
		"welcome":     true,
		"welcome1":    true,
		"welcome123":  true,
		"passw0rd":    true,
		"p@ssw0rd":    true,
		"p@ssword":    true,
		"letmein123":  true,
		"qwerty123":   true,
	}

	return commonPasswords[password]
}

// itoa is a simple int to string conversion (to avoid importing strconv)
func itoa(i int) string {
	if i == 0 {
		return "0"
	}

	negative := i < 0
	if negative {
		i = -i
	}

	var digits []byte
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}

	if negative {
		digits = append([]byte{'-'}, digits...)
	}

	return string(digits)
}

// GetPasswordStrengthLabel returns a human-readable strength label
func GetPasswordStrengthLabel(score int) string {
	switch {
	case score >= 80:
		return "Strong"
	case score >= 60:
		return "Good"
	case score >= 40:
		return "Fair"
	case score >= 20:
		return "Weak"
	default:
		return "Very Weak"
	}
}
