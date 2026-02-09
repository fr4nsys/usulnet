// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package executor provides Docker options converters from protocol parameters.
package executor

import (
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/volume"

	"github.com/fr4nsys/usulnet/internal/gateway/protocol"
)

// ============================================================================
// Container Options
// ============================================================================

func containerListOptionsFromParams(p protocol.CommandParams) container.ListOptions {
	opts := container.ListOptions{
		All:   p.All,
		Limit: p.Limit,
	}

	if len(p.Filters) > 0 {
		opts.Filters = filtersFromMap(p.Filters)
	}

	return opts
}

func containerStartOptionsFromParams(p protocol.CommandParams) container.StartOptions {
	return container.StartOptions{}
}

func containerStopOptionsFromParams(p protocol.CommandParams) container.StopOptions {
	opts := container.StopOptions{}

	if p.StopTimeout != nil {
		timeout := *p.StopTimeout
		opts.Timeout = &timeout
	}

	if p.Signal != "" {
		opts.Signal = p.Signal
	}

	return opts
}

func containerRemoveOptionsFromParams(p protocol.CommandParams) container.RemoveOptions {
	return container.RemoveOptions{
		RemoveVolumes: p.RemoveVolumes,
		Force:         p.Force,
	}
}

func containerLogsOptionsFromParams(p protocol.CommandParams) container.LogsOptions {
	opts := container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     p.Follow,
		Timestamps: p.Timestamps,
		Details:    p.Details,
	}

	if p.Tail != "" {
		opts.Tail = p.Tail
	} else {
		opts.Tail = "1000" // Default
	}

	if p.Since != "" {
		opts.Since = p.Since
	}

	if p.Until != "" {
		opts.Until = p.Until
	}

	return opts
}

func containerExecConfigFromParams(p protocol.CommandParams) container.ExecOptions {
	return container.ExecOptions{
		Cmd:          p.Cmd,
		Env:          p.Env,
		WorkingDir:   p.WorkingDir,
		User:         p.User,
		Tty:          p.Tty,
		AttachStdin:  p.AttachStdin,
		AttachStdout: p.AttachStdout,
		AttachStderr: p.AttachStderr,
		Privileged:   p.Privileged,
	}
}

// ============================================================================
// Image Options
// ============================================================================

func imageListOptionsFromParams(p protocol.CommandParams) image.ListOptions {
	opts := image.ListOptions{
		All: p.All,
	}

	if len(p.Filters) > 0 {
		opts.Filters = filtersFromMap(p.Filters)
	}

	return opts
}

func imagePullOptionsFromParams(p protocol.CommandParams) image.PullOptions {
	opts := image.PullOptions{}

	if p.Platform != "" {
		opts.Platform = p.Platform
	}

	// TODO: Add registry auth support
	return opts
}

func imageRemoveOptionsFromParams(p protocol.CommandParams) image.RemoveOptions {
	return image.RemoveOptions{
		Force:         p.Force,
		PruneChildren: true,
	}
}

func imagePruneFiltersFromParams(p protocol.CommandParams) filters.Args {
	f := filters.NewArgs()

	if p.PruneAll {
		f.Add("dangling", "false")
	} else {
		f.Add("dangling", "true")
	}

	if len(p.PruneFilters) > 0 {
		for key, values := range p.PruneFilters {
			for _, v := range values {
				f.Add(key, v)
			}
		}
	}

	return f
}

// ============================================================================
// Volume Options
// ============================================================================

func volumeListOptionsFromParams(p protocol.CommandParams) volume.ListOptions {
	opts := volume.ListOptions{}

	if len(p.Filters) > 0 {
		opts.Filters = filtersFromMap(p.Filters)
	}

	return opts
}

func volumeCreateOptionsFromParams(p protocol.CommandParams) volume.CreateOptions {
	opts := volume.CreateOptions{
		Name: p.VolumeName,
	}

	if p.Driver != "" {
		opts.Driver = p.Driver
	}

	if len(p.DriverOpts) > 0 {
		opts.DriverOpts = p.DriverOpts
	}

	return opts
}

func volumePruneFiltersFromParams(p protocol.CommandParams) filters.Args {
	f := filters.NewArgs()

	if len(p.PruneFilters) > 0 {
		for key, values := range p.PruneFilters {
			for _, v := range values {
				f.Add(key, v)
			}
		}
	}

	return f
}

// ============================================================================
// Network Options
// ============================================================================

func networkListOptionsFromParams(p protocol.CommandParams) network.ListOptions {
	opts := network.ListOptions{}

	if len(p.Filters) > 0 {
		opts.Filters = filtersFromMap(p.Filters)
	}

	return opts
}

func networkInspectOptionsFromParams(p protocol.CommandParams) network.InspectOptions {
	return network.InspectOptions{
		Verbose: p.Details,
	}
}

func networkCreateOptionsFromParams(p protocol.CommandParams) network.CreateOptions {
	opts := network.CreateOptions{
		Driver:     p.Driver,
		Internal:   p.Internal,
		Attachable: p.Attachable,
	}

	if opts.Driver == "" {
		opts.Driver = "bridge"
	}

	// Configure IPAM if subnet specified
	if p.Subnet != "" {
		ipamConfig := network.IPAMConfig{
			Subnet:  p.Subnet,
			Gateway: p.Gateway,
		}
		opts.IPAM = &network.IPAM{
			Driver: "default",
			Config: []network.IPAMConfig{ipamConfig},
		}
	}

	return opts
}

func networkConnectOptionsFromParams(p protocol.CommandParams) *network.EndpointSettings {
	settings := &network.EndpointSettings{}

	if p.IPAddress != "" {
		settings.IPAMConfig = &network.EndpointIPAMConfig{
			IPv4Address: p.IPAddress,
		}
	}

	if len(p.Aliases) > 0 {
		settings.Aliases = p.Aliases
	}

	return settings
}

// ============================================================================
// System Options
// ============================================================================

func diskUsageOptionsFromParams(p protocol.CommandParams) types.DiskUsageOptions {
	return types.DiskUsageOptions{}
}

// ============================================================================
// Filter Helpers
// ============================================================================

func filtersFromMap(m map[string][]string) filters.Args {
	f := filters.NewArgs()
	for key, values := range m {
		for _, v := range values {
			f.Add(key, v)
		}
	}
	return f
}

// ============================================================================
// Time Helpers
// ============================================================================

func durationPtr(d time.Duration) *time.Duration {
	return &d
}

func intPtr(i int) *int {
	return &i
}
