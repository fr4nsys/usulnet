// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package validator

import (
	"reflect"
	"regexp"
	"strings"
	"sync"

	"github.com/go-playground/validator/v10"
)

var (
	once     sync.Once
	validate *validator.Validate
)

// Validator wraps go-playground/validator with custom validations
type Validator struct {
	v *validator.Validate
}

// New creates a new Validator instance
func New() *Validator {
	once.Do(func() {
		validate = validator.New()

		// Use JSON tag names for field errors
		validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
			name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
			if name == "-" {
				return ""
			}
			return name
		})

		// Register custom validations
		registerCustomValidations(validate)
	})

	return &Validator{v: validate}
}

// Validate validates a struct and returns validation errors
func (v *Validator) Validate(i interface{}) error {
	return v.v.Struct(i)
}

// ValidateVar validates a single variable
func (v *Validator) ValidateVar(field interface{}, tag string) error {
	return v.v.Var(field, tag)
}

// ValidationErrors extracts field errors as a map
func (v *Validator) ValidationErrors(err error) map[string]string {
	if err == nil {
		return nil
	}

	errs, ok := err.(validator.ValidationErrors)
	if !ok {
		return map[string]string{"_error": err.Error()}
	}

	result := make(map[string]string)
	for _, e := range errs {
		field := e.Field()
		result[field] = formatValidationError(e)
	}
	return result
}

// formatValidationError formats a single validation error
func formatValidationError(e validator.FieldError) string {
	switch e.Tag() {
	case "required":
		return "is required"
	case "email":
		return "must be a valid email address"
	case "min":
		return "must be at least " + e.Param() + " characters"
	case "max":
		return "must be at most " + e.Param() + " characters"
	case "gte":
		return "must be greater than or equal to " + e.Param()
	case "lte":
		return "must be less than or equal to " + e.Param()
	case "gt":
		return "must be greater than " + e.Param()
	case "lt":
		return "must be less than " + e.Param()
	case "len":
		return "must be exactly " + e.Param() + " characters"
	case "oneof":
		return "must be one of: " + e.Param()
	case "url":
		return "must be a valid URL"
	case "uuid":
		return "must be a valid UUID"
	case "alphanum":
		return "must contain only alphanumeric characters"
	case "alpha":
		return "must contain only letters"
	case "numeric":
		return "must contain only numbers"
	case "hostname":
		return "must be a valid hostname"
	case "hostname_port":
		return "must be a valid hostname:port"
	case "ip":
		return "must be a valid IP address"
	case "ipv4":
		return "must be a valid IPv4 address"
	case "ipv6":
		return "must be a valid IPv6 address"
	case "cidr":
		return "must be a valid CIDR notation"
	case "username":
		return "must be a valid username (alphanumeric, underscore, 3-32 chars)"
	case "password_strength":
		return "password does not meet strength requirements"
	case "docker_image":
		return "must be a valid Docker image reference"
	case "docker_container_name":
		return "must be a valid Docker container name"
	default:
		return "is invalid"
	}
}

// registerCustomValidations registers custom validation rules
func registerCustomValidations(v *validator.Validate) {
	// Username validation: alphanumeric + underscore, 3-32 chars
	_ = v.RegisterValidation("username", func(fl validator.FieldLevel) bool {
		username := fl.Field().String()
		if len(username) < 3 || len(username) > 32 {
			return false
		}
		matched, _ := regexp.MatchString(`^[a-zA-Z][a-zA-Z0-9_]*$`, username)
		return matched
	})

	// Password strength validation
	_ = v.RegisterValidation("password_strength", func(fl validator.FieldLevel) bool {
		password := fl.Field().String()
		if len(password) < 8 {
			return false
		}
		// At least one uppercase, one lowercase, one digit
		hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
		hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
		hasDigit := regexp.MustCompile(`[0-9]`).MatchString(password)
		return hasUpper && hasLower && hasDigit
	})

	// Docker image reference validation
	_ = v.RegisterValidation("docker_image", func(fl validator.FieldLevel) bool {
		image := fl.Field().String()
		// Basic validation: registry/repo:tag format
		// Allows: nginx, nginx:latest, docker.io/nginx:1.25, ghcr.io/user/repo:tag
		matched, _ := regexp.MatchString(`^[a-zA-Z0-9][a-zA-Z0-9._/-]*(:[\w][\w.-]*)?(@sha256:[a-f0-9]{64})?$`, image)
		return matched
	})

	// Docker container name validation
	_ = v.RegisterValidation("docker_container_name", func(fl validator.FieldLevel) bool {
		name := fl.Field().String()
		// Docker container names: [a-zA-Z0-9][a-zA-Z0-9_.-]
		if len(name) < 1 || len(name) > 128 {
			return false
		}
		matched, _ := regexp.MatchString(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`, name)
		return matched
	})

	// Cron expression validation (basic)
	_ = v.RegisterValidation("cron", func(fl validator.FieldLevel) bool {
		cron := fl.Field().String()
		// Basic cron format: 5 or 6 fields separated by spaces
		fields := strings.Fields(cron)
		return len(fields) >= 5 && len(fields) <= 6
	})

	// Hex string validation
	_ = v.RegisterValidation("hexstring", func(fl validator.FieldLevel) bool {
		s := fl.Field().String()
		matched, _ := regexp.MatchString(`^[a-fA-F0-9]+$`, s)
		return matched
	})

	// Base64 string validation
	_ = v.RegisterValidation("base64", func(fl validator.FieldLevel) bool {
		s := fl.Field().String()
		matched, _ := regexp.MatchString(`^[A-Za-z0-9+/]*={0,2}$`, s)
		return matched
	})

	// Port number validation
	_ = v.RegisterValidation("port", func(fl validator.FieldLevel) bool {
		port := fl.Field().Int()
		return port >= 1 && port <= 65535
	})
}

// Global convenience functions

// Validate validates a struct using the global validator
func Validate(i interface{}) error {
	return New().Validate(i)
}

// ValidateVar validates a single variable using the global validator
func ValidateVar(field interface{}, tag string) error {
	return New().ValidateVar(field, tag)
}

// GetValidationErrors extracts validation errors as a map
func GetValidationErrors(err error) map[string]string {
	return New().ValidationErrors(err)
}
