// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package utils

import (
	"bytes"
	"encoding/json"
	"io"
)

// MustMarshal marshals v to JSON, panics on error
// Use only when failure is unexpected/unrecoverable
func MustMarshal(v interface{}) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}

// MustMarshalIndent marshals v to indented JSON, panics on error
func MustMarshalIndent(v interface{}) []byte {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	return data
}

// MarshalString marshals v to a JSON string
func MarshalString(v interface{}) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// MustMarshalString marshals v to a JSON string, panics on error
func MustMarshalString(v interface{}) string {
	return string(MustMarshal(v))
}

// UnmarshalString unmarshals a JSON string into v
func UnmarshalString(s string, v interface{}) error {
	return json.Unmarshal([]byte(s), v)
}

// Clone creates a deep copy of v by marshaling/unmarshaling JSON
func Clone[T any](v T) (T, error) {
	var result T
	data, err := json.Marshal(v)
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(data, &result)
	return result, err
}

// MustClone creates a deep copy, panics on error
func MustClone[T any](v T) T {
	result, err := Clone(v)
	if err != nil {
		panic(err)
	}
	return result
}

// PrettyPrint returns a pretty-printed JSON string
func PrettyPrint(v interface{}) string {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return ""
	}
	return string(data)
}

// Compact removes whitespace from JSON
func Compact(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := json.Compact(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Valid checks if data is valid JSON
func Valid(data []byte) bool {
	return json.Valid(data)
}

// ValidString checks if s is valid JSON
func ValidString(s string) bool {
	return json.Valid([]byte(s))
}

// Merge merges multiple JSON objects
func Merge(objects ...map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for _, obj := range objects {
		for k, v := range obj {
			result[k] = v
		}
	}
	return result
}

// GetString gets a string value from a JSON object
func GetString(obj map[string]interface{}, key string) string {
	if v, ok := obj[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// GetInt gets an int value from a JSON object
func GetInt(obj map[string]interface{}, key string) int {
	if v, ok := obj[key]; ok {
		switch n := v.(type) {
		case int:
			return n
		case int64:
			return int(n)
		case float64:
			return int(n)
		}
	}
	return 0
}

// GetBool gets a bool value from a JSON object
func GetBool(obj map[string]interface{}, key string) bool {
	if v, ok := obj[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

// GetSlice gets a slice value from a JSON object
func GetSlice(obj map[string]interface{}, key string) []interface{} {
	if v, ok := obj[key]; ok {
		if s, ok := v.([]interface{}); ok {
			return s
		}
	}
	return nil
}

// GetMap gets a map value from a JSON object
func GetMap(obj map[string]interface{}, key string) map[string]interface{} {
	if v, ok := obj[key]; ok {
		if m, ok := v.(map[string]interface{}); ok {
			return m
		}
	}
	return nil
}

// ReadJSON reads JSON from an io.Reader into v
func ReadJSON(r io.Reader, v interface{}) error {
	return json.NewDecoder(r).Decode(v)
}

// WriteJSON writes v as JSON to an io.Writer
func WriteJSON(w io.Writer, v interface{}) error {
	return json.NewEncoder(w).Encode(v)
}

// ToMap converts a struct to a map using JSON marshaling
func ToMap(v interface{}) (map[string]interface{}, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// FromMap converts a map to a struct using JSON unmarshaling
func FromMap(m map[string]interface{}, v interface{}) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}
