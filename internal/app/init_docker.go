// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package app

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/jmoiron/sqlx"

	dockerpkg "github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	containersvc "github.com/fr4nsys/usulnet/internal/services/container"
	hostsvc "github.com/fr4nsys/usulnet/internal/services/host"
	imagesvc "github.com/fr4nsys/usulnet/internal/services/image"
	networksvc "github.com/fr4nsys/usulnet/internal/services/network"
	stacksvc "github.com/fr4nsys/usulnet/internal/services/stack"
	volumesvc "github.com/fr4nsys/usulnet/internal/services/volume"
)

// initDocker initializes the host service (standalone mode), the local Docker
// client, and the container/image/volume/network/stack services. It bootstraps
// the local-host DB row and kicks off an initial container sync so the
// dashboard has data immediately.
func (app *Application) initDocker(ctx context.Context, ic *initContext) error {
	defaultHostID := standaloneHostID

	hostService := hostsvc.NewStandaloneService(hostsvc.DefaultConfig(), app.Logger)
	app.hostService = hostService

	// Wire host repository so Create/Update/Delete hosts work in standalone mode.
	stdDBHosts := stdlib.OpenDBFromPool(app.DB.Pool())
	hostRepo := postgres.NewHostRepository(sqlx.NewDb(stdDBHosts, "pgx"))
	hostService.SetRepository(hostRepo)

	dockerClient, err := dockerpkg.NewLocalClient(ctx)
	if err != nil {
		app.Logger.Error("Failed to connect to local Docker", "error", err)
		// Non-fatal: services return errors but the app still serves the UI.
	} else {
		hostService.RegisterClient(defaultHostID.String(), dockerClient)
		app.Logger.Info("Connected to local Docker engine")
	}

	if err := hostService.Start(ctx); err != nil {
		app.Logger.Error("Failed to start host service", "error", err)
	}

	if err := app.bootstrapLocalHost(ctx, defaultHostID); err != nil {
		app.Logger.Error("Failed to bootstrap local host in DB", "error", err)
	}

	containerRepo := postgres.NewContainerRepository(app.DB)
	containerService := containersvc.NewService(containerRepo, hostService, containersvc.DefaultConfig(), app.Logger)
	app.containerService = containerService
	if err := containerService.Start(ctx); err != nil {
		app.Logger.Error("Failed to start container service", "error", err)
	}

	// Initial sync so the dashboard has data immediately.
	go func() {
		select {
		case <-time.After(1 * time.Second):
		case <-ctx.Done():
			return
		}
		if err := containerService.SyncHost(ctx, defaultHostID); err != nil {
			app.Logger.Warn("Initial container sync failed (will retry on next interval)", "error", err)
		} else {
			app.Logger.Info("Initial container sync completed")
		}
	}()

	imageService := imagesvc.NewService(hostService, app.Logger)
	volumeService := volumesvc.NewService(hostService, app.Logger)
	networkService := networksvc.NewService(hostService, app.Logger)

	stackRepo := postgres.NewStackRepository(app.DB)
	stackService := stacksvc.NewService(stackRepo, hostService, containerService, stacksvc.ServiceConfig{
		StacksDir:      "/app/data/stacks",
		ComposeCommand: "docker compose",
		DefaultTimeout: 5 * time.Minute,
	}, app.Logger)

	app.Logger.Info("Docker services initialized",
		"host_id", defaultHostID,
		"sync_interval", "30s",
	)

	ic.defaultHostID = defaultHostID
	ic.hostService = hostService
	ic.containerService = containerService
	ic.containerRepo = containerRepo
	ic.imageService = imageService
	ic.volumeService = volumeService
	ic.networkService = networkService
	ic.stackService = stackService
	ic.dockerClient = dockerClient

	return nil
}
