// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	networksvc "github.com/fr4nsys/usulnet/internal/services/network"
)

type networkAdapter struct {
	svc    *networksvc.Service
	hostID uuid.UUID
}

func (a *networkAdapter) List(ctx context.Context) ([]NetworkView, error) {
	if a.svc == nil {
		return nil, nil
	}

	networks, err := a.svc.List(ctx, resolveHostID(ctx, a.hostID))
	if err != nil {
		return nil, err
	}

	views := make([]NetworkView, 0, len(networks))
	for _, n := range networks {
		views = append(views, networkToView(n))
	}
	return views, nil
}

func (a *networkAdapter) Get(ctx context.Context, id string) (*NetworkView, error) {
	if a.svc == nil {
		return nil, nil
	}

	n, err := a.svc.Get(ctx, resolveHostID(ctx, a.hostID), id)
	if err != nil {
		return nil, err
	}

	view := networkToView(n)
	return &view, nil
}

func (a *networkAdapter) GetModel(ctx context.Context, id string) (*models.Network, error) {
	if a.svc == nil {
		return nil, nil
	}
	return a.svc.Get(ctx, resolveHostID(ctx, a.hostID), id)
}

func (a *networkAdapter) Create(ctx context.Context, name, driver string, opts map[string]string) error {
	if a.svc == nil {
		return ErrServiceNotConfigured
	}

	input := &models.CreateNetworkInput{
		Name:   name,
		Driver: driver,
	}
	_, err := a.svc.Create(ctx, resolveHostID(ctx, a.hostID), input)
	return err
}

func (a *networkAdapter) Remove(ctx context.Context, id string) error {
	if a.svc == nil {
		return ErrServiceNotConfigured
	}
	return a.svc.Delete(ctx, resolveHostID(ctx, a.hostID), id)
}

func (a *networkAdapter) Connect(ctx context.Context, networkID, containerID string) error {
	if a.svc == nil {
		return ErrServiceNotConfigured
	}
	return a.svc.Connect(ctx, resolveHostID(ctx, a.hostID), networkID, containerID, nil)
}

func (a *networkAdapter) Disconnect(ctx context.Context, networkID, containerID string) error {
	if a.svc == nil {
		return ErrServiceNotConfigured
	}
	return a.svc.Disconnect(ctx, resolveHostID(ctx, a.hostID), networkID, containerID, false)
}

func (a *networkAdapter) Prune(ctx context.Context) (int64, error) {
	if a.svc == nil {
		return 0, ErrServiceNotConfigured
	}
	result, err := a.svc.Prune(ctx, resolveHostID(ctx, a.hostID))
	if err != nil {
		return 0, err
	}
	return int64(len(result.ItemsDeleted)), nil
}

func (a *networkAdapter) GetTopology(ctx context.Context) (*TopologyData, error) {
	if a.svc == nil {
		return nil, nil
	}

	topo, err := a.svc.GetTopology(ctx, resolveHostID(ctx, a.hostID))
	if err != nil {
		return nil, err
	}

	// Convert map[string][]string to TopologyData with Nodes/Edges
	data := &TopologyData{
		Nodes: make([]TopologyNode, 0),
		Edges: make([]TopologyEdge, 0),
	}

	// Add network nodes and edges
	for networkID, containerIDs := range topo {
		// Add network node
		data.Nodes = append(data.Nodes, TopologyNode{
			ID:    networkID,
			Label: networkID,
			Type:  "network",
		})

		// Add edges to containers
		for _, containerID := range containerIDs {
			// Add container node if not exists (simplified, may have duplicates)
			data.Nodes = append(data.Nodes, TopologyNode{
				ID:    containerID,
				Label: containerID,
				Type:  "container",
			})

			data.Edges = append(data.Edges, TopologyEdge{
				From: networkID,
				To:   containerID,
			})
		}
	}

	return data, nil
}
