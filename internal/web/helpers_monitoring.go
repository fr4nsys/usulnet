// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	dockerClient "github.com/docker/docker/client"

	"github.com/fr4nsys/usulnet/internal/docker"
)

// jsonDecoder creates a JSON decoder from any io.Reader.
// Used by handler_monitoring.go for decoding Docker stats responses.
func jsonDecoder(r io.Reader) *json.Decoder {
	return json.NewDecoder(r)
}

// getDockerClient returns the raw Docker SDK client for the current host.
// Used by monitoring handlers that need direct Docker API access.
// Returns an error for remote agent hosts (monitoring uses direct Docker API).
func (h *Handler) getDockerClient(r *http.Request) (*dockerClient.Client, error) {
	cli, err := h.services.Containers().GetDockerClient(r.Context())
	if err != nil {
		return nil, err
	}
	directClient, ok := cli.(*docker.Client)
	if !ok {
		return nil, fmt.Errorf("direct Docker API access not available for remote hosts")
	}
	return directClient.Raw(), nil
}
