// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package toolkit

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/fr4nsys/usulnet/internal/services/recon"
)

// subfinderModule is the profile module name the engine routes here.
const subfinderModule = "subfinder"

// CategorySubdomain is the recon.Finding.Category every event from
// this wrapper carries.
const CategorySubdomain = "subdomain"

// subfinderJSON mirrors the shape entrypoint.sh emits:
//
//	{"domain": "...", "subdomains": [{"host":"a.example.com","source":"..."}, ...]}
type subfinderJSON struct {
	Domain     string             `json:"domain"`
	Subdomains []subfinderSubItem `json:"subdomains"`
}

// subfinderSubItem is one row of subfinder's -json output. Subfinder
// emits a few fields; "host" is the only one every release uses.
type subfinderSubItem struct {
	Host   string `json:"host"`
	Source string `json:"source"`
	Input  string `json:"input"`
}

// subfinderRunner is the moduleRunner implementation for subfinder.
type subfinderRunner struct{}

// Module implements moduleRunner.
func (subfinderRunner) Module() string { return subfinderModule }

// Run implements moduleRunner. Each discovered subdomain becomes an
// EngineEvent at info severity with confidence 70 (matching the
// per-tool mapping decisions documented in session 07).
func (subfinderRunner) Run(
	ctx context.Context,
	target recon.Target,
	launcher recon.ContainerLauncher,
	image string,
	timeout time.Duration,
) ([]recon.EngineEvent, error) {
	domain := strings.TrimSpace(target.Value)
	if domain == "" {
		return nil, fmt.Errorf("toolkit: subfinder: empty target domain")
	}

	cmd := []string{"subfinder", "--domain", domain}
	var dst subfinderJSON
	_, err := runToolkitJSON(ctx, launcher, image, cmd, timeout, &dst)
	if err != nil {
		return nil, err
	}

	out := make([]recon.EngineEvent, 0, len(dst.Subdomains))
	for _, sub := range dst.Subdomains {
		host := strings.TrimSpace(sub.Host)
		if host == "" {
			continue
		}
		payload, _ := json.Marshal(sub)
		out = append(out, recon.EngineEvent{
			Module:     subfinderModule,
			Category:   CategorySubdomain,
			Severity:   recon.SeverityInfo,
			Value:      host,
			Source:     sub.Source,
			Confidence: 70,
			RawPayload: payload,
		})
	}
	return out, nil
}
