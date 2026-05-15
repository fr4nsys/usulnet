// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package executor

import (
	"strings"
	"testing"
)

func TestValidateInterfaceName(t *testing.T) {
	good := []string{"wg0", "wg-mesh", "wg_a", "abcDEF12345"}
	bad := []string{"", "way-too-long-name-here", "wg 0", "wg;rm", "wg/0", "wg.0"}
	for _, s := range good {
		if err := validateInterfaceName(s); err != nil {
			t.Errorf("validateInterfaceName(%q) unexpected error: %v", s, err)
		}
	}
	for _, s := range bad {
		if err := validateInterfaceName(s); err == nil {
			t.Errorf("validateInterfaceName(%q) expected error, got nil", s)
		}
	}
}

func TestValidateBase64Key(t *testing.T) {
	// Valid 32-byte key encoded as base64 (44 chars ending in =).
	good := "qEKa7E0bM0aiGkv9MeUI1A8AwlGc2sH5lkLm0Yjtn1c="
	if err := validateBase64Key(good); err != nil {
		t.Errorf("validateBase64Key(good) returned error: %v", err)
	}
	bad := []string{
		"",
		"too-short",
		strings.Repeat("a", 44) + "!", // invalid char
		strings.Repeat("a", 50),       // too long
	}
	for _, s := range bad {
		if err := validateBase64Key(s); err == nil {
			t.Errorf("validateBase64Key(%q) expected error", s)
		}
	}
}

func TestValidateAllowedIPs(t *testing.T) {
	good := []string{
		"",
		"10.0.0.0/24",
		"10.0.0.0/24, 10.1.0.0/24",
		"fd00::/8",
	}
	bad := []string{
		"10.0.0.0/24; rm -rf",
		"10.0.0.0/24 | nc evil",
	}
	for _, s := range good {
		if err := validateAllowedIPs(s); err != nil {
			t.Errorf("validateAllowedIPs(%q): %v", s, err)
		}
	}
	for _, s := range bad {
		if err := validateAllowedIPs(s); err == nil {
			t.Errorf("validateAllowedIPs(%q) expected error", s)
		}
	}
}

func TestValidateEndpoint(t *testing.T) {
	good := []string{
		"vpn.example.com:51820",
		"10.0.0.1:51820",
		"[2001:db8::1]:51820",
	}
	bad := []string{
		"",
		"no-port",
		"vpn.example.com:51820; whoami",
	}
	for _, s := range good {
		if err := validateEndpoint(s); err != nil {
			t.Errorf("validateEndpoint(%q): %v", s, err)
		}
	}
	for _, s := range bad {
		if err := validateEndpoint(s); err == nil {
			t.Errorf("validateEndpoint(%q) expected error", s)
		}
	}
}

func TestTrimKey(t *testing.T) {
	if got := trimKey("short"); got != "short" {
		t.Errorf("trimKey(short)=%q", got)
	}
	got := trimKey("0123456789abcdefghij")
	if !strings.HasSuffix(got, "…") {
		t.Errorf("trimKey did not truncate: %q", got)
	}
}
