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

// katanaModule is the profile module name the engine routes here.
const katanaModule = "katana"

// CategoryDeepLink is the recon.Finding.Category every event from
// this wrapper carries.
const CategoryDeepLink = "deep_link"

// katanaJSON mirrors the shape entrypoint.sh emits:
//
//	{"seed": "...", "urls": [{"timestamp":"...","request":{"endpoint":"..."}}, ...]}
//
// Katana's -jsonl output evolves between releases; we keep the
// parser tolerant by only requiring an "endpoint" field and falling
// back to a top-level "url" when present.
type katanaJSON struct {
	Seed string         `json:"seed"`
	URLs []katanaURLRow `json:"urls"`
}

// katanaURLRow is one row of katana's -jsonl output.
type katanaURLRow struct {
	Timestamp string `json:"timestamp"`
	URL       string `json:"url"`
	Request   struct {
		Endpoint string `json:"endpoint"`
		Method   string `json:"method"`
	} `json:"request"`
}

// katanaRunner is the moduleRunner implementation for katana.
type katanaRunner struct{}

// Module implements moduleRunner.
func (katanaRunner) Module() string { return katanaModule }

// Run implements moduleRunner. Each crawled URL becomes an
// EngineEvent at info severity with confidence 60.
func (katanaRunner) Run(
	ctx context.Context,
	target recon.Target,
	launcher recon.ContainerLauncher,
	image string,
	timeout time.Duration,
) ([]recon.EngineEvent, error) {
	seed := strings.TrimSpace(target.Value)
	if seed == "" {
		return nil, fmt.Errorf("toolkit: katana: empty target url")
	}

	cmd := []string{"katana", "--url", seed}
	var dst katanaJSON
	_, err := runToolkitJSON(ctx, launcher, image, cmd, timeout, &dst)
	if err != nil {
		return nil, err
	}

	out := make([]recon.EngineEvent, 0, len(dst.URLs))
	for _, row := range dst.URLs {
		endpoint := strings.TrimSpace(row.Request.Endpoint)
		if endpoint == "" {
			endpoint = strings.TrimSpace(row.URL)
		}
		if endpoint == "" {
			continue
		}
		payload, _ := json.Marshal(row)
		out = append(out, recon.EngineEvent{
			Module:     katanaModule,
			Category:   CategoryDeepLink,
			Severity:   recon.SeverityInfo,
			Value:      endpoint,
			Source:     seed,
			Confidence: 60,
			RawPayload: payload,
		})
	}
	return out, nil
}
