// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package wiring constructs the recon module's runtime objects behind
// the cfg.Recon.Enabled feature flag.
//
// It lives in its own package so the feature-flag gating can be unit
// tested without dragging in the whole app/ package dependency graph
// (which transitively includes the web layer and a great many other
// services). The package is consumed from internal/app/app.go.
package wiring

import (
	"context"
	"fmt"
	"path/filepath"

	dockerpkg "github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	"github.com/fr4nsys/usulnet/internal/scheduler/workers"
	"github.com/fr4nsys/usulnet/internal/services/metadata"
	"github.com/fr4nsys/usulnet/internal/services/metadata/artifactstore"
	"github.com/fr4nsys/usulnet/internal/services/metadata/extractor"
	"github.com/fr4nsys/usulnet/internal/services/metadata/stripper"
	"github.com/fr4nsys/usulnet/internal/services/recon"
	reconsandbox "github.com/fr4nsys/usulnet/internal/services/recon/sandbox"
)

// Config is the subset of internal/app.ReconConfig that buildReconModule
// needs. Keeping it as a local type avoids an import cycle with the
// app package and lets tests construct it directly.
type Config struct {
	Enabled            bool
	RetentionDays      int
	MaxConcurrentScans int
	InstallationOrg    string
	BaseURL            string
	EgressAllowlist    []string
}

// Module is the bag of recon-related runtime objects produced by
// Build when Config.Enabled is true.
type Module struct {
	Launcher recon.ContainerLauncher

	// Service is the concrete recon.Service. It is non-nil whenever
	// the database is wired; otherwise the app keeps ReconHandler.svc
	// at nil and the API surface degrades to 503 engine_unavailable.
	Service recon.Service

	MetadataService  workers.MetadataJobService
	ReconScanService workers.ReconScanService
	Verifiers        map[recon.OwnershipMethod]recon.OwnershipVerifier
	RDAPClient       *recon.RDAPClient
}

// LauncherFactory is the seam unit tests use to assert that disabled
// installs never construct a launcher. Production wiring passes
// DefaultLauncherFactory.
type LauncherFactory func(client *dockerpkg.Client, cfg reconsandbox.Config, log *logger.Logger) (recon.ContainerLauncher, error)

// DefaultLauncherFactory is the production launcher constructor.
func DefaultLauncherFactory(client *dockerpkg.Client, cfg reconsandbox.Config, log *logger.Logger) (recon.ContainerLauncher, error) {
	return reconsandbox.NewLauncher(client, cfg, log)
}

// Deps is the constructor input.
type Deps struct {
	DB           *postgres.DB
	DockerClient *dockerpkg.Client
	Encryptor    *crypto.AESEncryptor
	StoragePath  string
	EmailSender  recon.EmailSender
	Logger       *logger.Logger

	// LauncherFact is the launcher constructor. Tests override it with
	// a counting double; production callers leave it nil to use
	// DefaultLauncherFactory.
	LauncherFact LauncherFactory
}

// Build constructs the recon runtime. It returns (nil, nil) when
// cfg.Enabled is false — and does NOT call any sub-constructors,
// including the launcher factory. The contract is verified by
// TestBuild_DisabledShortCircuits.
//
// Errors at this stage are intentionally non-fatal: an operator running
// usulnet without local Docker should still see the binary start, with
// the recon engines logged as unavailable. The function returns nil
// for sub-components that failed to construct.
func Build(ctx context.Context, cfg Config, deps Deps) (*Module, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	log := deps.Logger
	if log == nil {
		log = logger.Nop()
	}
	log = log.Named("recon.wiring")

	factory := deps.LauncherFact
	if factory == nil {
		factory = DefaultLauncherFactory
	}

	m := &Module{
		Verifiers: make(map[recon.OwnershipMethod]recon.OwnershipVerifier, 5),
	}

	// ---- Sandbox launcher (lazy by construction) ------------------------
	if deps.DockerClient != nil {
		launcher, err := factory(deps.DockerClient, reconsandbox.Config{
			EgressAllowlist: cfg.EgressAllowlist,
		}, log)
		if err != nil {
			log.Warn("recon launcher construction failed; engine paths disabled",
				"error", err,
			)
		} else {
			m.Launcher = launcher
		}
	} else {
		log.Warn("recon enabled but local Docker client unavailable; engine paths disabled")
	}

	// ---- Metadata service + worker --------------------------------------
	if deps.DB != nil {
		metaRepo := postgres.NewReconMetadataRepository(deps.DB)
		artifactRoot := filepath.Join(deps.StoragePath, "recon", "artifacts")
		store, err := artifactstore.NewLocalStore(artifactRoot)
		if err != nil {
			log.Warn("recon metadata: local artifact store unavailable",
				"path", artifactRoot,
				"error", err,
			)
		} else {
			ext, str, err := buildMetadataToolchain(m.Launcher, log)
			if err != nil {
				log.Warn("recon metadata: extractor/stripper construction failed",
					"error", err,
				)
			} else {
				metaCfg := metadata.Config{
					DataDir:       deps.StoragePath,
					RetentionDays: cfg.RetentionDays,
				}
				svc, err := metadata.NewService(metaRepo, store, ext, str, metaCfg, log)
				if err != nil {
					log.Warn("recon metadata: service construction failed",
						"error", err,
					)
				} else {
					m.MetadataService = svc
					log.Info("recon metadata service wired",
						"data_dir", deps.StoragePath,
					)
				}
			}
		}
	}

	// ---- Ownership verifiers --------------------------------------------
	m.RDAPClient = recon.NewRDAPClient(0)
	m.Verifiers[recon.OwnershipDNSTXT] = recon.NewDNSTXTVerifier(recon.DefaultDNSResolver(), log)
	m.Verifiers[recon.OwnershipEmailLink] = recon.NewEmailLinkVerifier(deps.EmailSender, cfg.BaseURL, log)
	m.Verifiers[recon.OwnershipRDAPMatch] = recon.NewRDAPVerifier(m.RDAPClient, cfg.InstallationOrg, log)
	m.Verifiers[recon.OwnershipSelfAssert] = recon.NewSelfAssertVerifier(log)

	if deps.DB != nil && deps.Encryptor != nil {
		reconRepo := postgres.NewReconRepository(deps.DB, deps.Encryptor)
		m.Verifiers[recon.OwnershipAdminAttest] = recon.NewAdminAttestVerifier(reconRepo, log)
	} else {
		m.Verifiers[recon.OwnershipAdminAttest] = recon.NewAdminAttestVerifier(nil, log)
		log.Warn("recon admin-attest verifier wired without audit sink")
	}
	log.Info("recon ownership verifiers wired",
		"methods", len(m.Verifiers),
	)

	// ---- Recon service (Session 02) ------------------------------------
	//
	// The Service is constructed whenever the database is wired. The
	// engines map is empty for now: the SpiderFoot adapter (S06) and
	// the toolkit adapter (S07) exist but the cross-wire from
	// launcher → container → engine is the work of a follow-up
	// session. Until then, request-handling paths (Targets / Profiles
	// / Scans / Findings CRUD) work end-to-end; calling RunScan on a
	// queued scan correctly returns ErrEngineUnavailable.
	if deps.DB != nil && deps.Encryptor != nil {
		reconRepo := postgres.NewReconRepository(deps.DB, deps.Encryptor)
		svc, err := recon.NewService(
			reconRepo,
			map[string]recon.Engine{},
			m.Verifiers,
			recon.DefaultClock(),
			recon.Config{},
			log,
		)
		if err != nil {
			log.Warn("recon service construction failed",
				"error", err,
			)
		} else {
			m.Service = svc
			m.ReconScanService = svc
			log.Info("recon service wired (engines pending S06/S07 cross-wire)")
		}
	}

	_ = ctx
	return m, nil
}

// buildMetadataToolchain assembles an Extractor + Stripper. With no
// launcher (no Docker), the stub implementations land so the service
// stays constructible but actual extract/strip calls degrade visibly.
func buildMetadataToolchain(launcher recon.ContainerLauncher, log *logger.Logger) (metadata.Extractor, metadata.Stripper, error) {
	if launcher == nil {
		return &extractor.Stub{}, &stripper.Stub{}, nil
	}
	exif, err := extractor.NewExifTool(launcher, recon.ToolkitImage(), 0, log)
	if err != nil {
		return nil, nil, fmt.Errorf("exiftool: %w", err)
	}
	pdfid, err := extractor.NewPDFID(launcher, recon.ToolkitImage(), 0, log)
	if err != nil {
		return nil, nil, fmt.Errorf("pdfid: %w", err)
	}
	oletools, err := extractor.NewOleTools(launcher, recon.ToolkitImage(), 0, log)
	if err != nil {
		return nil, nil, fmt.Errorf("oletools: %w", err)
	}
	dispatch, err := extractor.NewDispatch(exif, pdfid, oletools, log)
	if err != nil {
		return nil, nil, fmt.Errorf("dispatch: %w", err)
	}
	mat2, err := stripper.NewMat2(launcher, recon.ToolkitImage(), 0, log)
	if err != nil {
		return nil, nil, fmt.Errorf("mat2: %w", err)
	}
	return dispatch, mat2, nil
}

// Compile-time guarantee that the metadata service satisfies the
// worker's narrow interface.
var _ workers.MetadataJobService = (*metadata.Implementation)(nil)
