// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package app

import (
	"context"
	"fmt"

	"github.com/fr4nsys/usulnet/internal/nats"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	"github.com/fr4nsys/usulnet/internal/repository/redis"
)

// connectPostgres opens the PostgreSQL pool, runs schema migrations, and
// returns the live *postgres.DB. The caller owns deferring db.Close().
func connectPostgres(ctx context.Context, cfg *Config, log *logger.Logger) (*postgres.DB, error) {
	dbURL := cfg.EffectiveDatabaseURL()

	log.Info("Connecting to PostgreSQL...", "sslmode", cfg.Database.SSLMode)
	db, err := postgres.New(ctx, dbURL, postgres.Options{
		MaxOpenConns:    cfg.Database.MaxOpenConns,
		MaxIdleConns:    cfg.Database.MaxIdleConns,
		ConnMaxLifetime: cfg.Database.ConnMaxLifetime,
		ConnMaxIdleTime: cfg.Database.ConnMaxIdleTime,
		QueryTimeout:    cfg.Database.QueryTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}
	log.Info("PostgreSQL connected")

	log.Info("Running database migrations...")
	if err := db.Migrate(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}
	log.Info("Migrations completed")
	return db, nil
}

// connectRedis opens the Redis client. Caller owns deferring rdb.Close().
func connectRedis(ctx context.Context, cfg *Config, log *logger.Logger) (*redis.Client, error) {
	log.Info("Connecting to Redis...", "url", cfg.Redis.URL, "tls", cfg.Redis.TLSEnabled)
	rdb, err := redis.New(ctx, cfg.Redis.URL, redis.Options{
		PoolSize:      cfg.Redis.PoolSize,
		MinIdleConns:  cfg.Redis.MinIdleConns,
		DialTimeout:   cfg.Redis.DialTimeout,
		ReadTimeout:   cfg.Redis.ReadTimeout,
		WriteTimeout:  cfg.Redis.WriteTimeout,
		TLSEnabled:    cfg.Redis.TLSEnabled,
		TLSSkipVerify: cfg.Redis.TLSSkipVerify,
		TLSCAFile:     cfg.Redis.TLSCAFile,
		TLSCertFile:   cfg.Redis.TLSCertFile,
		TLSKeyFile:    cfg.Redis.TLSKeyFile,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}
	log.Info("Redis connected")
	return rdb, nil
}

// connectNATS opens the NATS client when required (master/agent or explicit
// URL). Returns (nil, nil) when NATS is not needed. Caller owns deferring
// nc.Close().
func connectNATS(ctx context.Context, cfg *Config, log *logger.Logger) (*nats.Client, error) {
	if cfg.Mode == "standalone" && cfg.NATS.URL == "" {
		return nil, nil
	}

	log.Info("Connecting to NATS...")
	natsCfg := nats.Config{
		URL:              cfg.NATS.URL,
		Name:             cfg.NATS.Name,
		Token:            cfg.NATS.Token,
		Username:         cfg.NATS.Username,
		Password:         cfg.NATS.Password,
		MaxReconnects:    cfg.NATS.MaxReconnects,
		ReconnectWait:    cfg.NATS.ReconnectWait,
		JetStreamEnabled: cfg.NATS.JetStream.Enabled,
		JetStreamDomain:  cfg.NATS.JetStream.Domain,
	}

	if cfg.NATS.TLS.Enabled {
		tlsCfg, tlsErr := buildNATSTLSConfig(cfg.NATS.TLS.CertFile, cfg.NATS.TLS.KeyFile, cfg.NATS.TLS.CAFile, cfg.NATS.TLS.SkipVerify)
		if tlsErr != nil {
			return nil, fmt.Errorf("failed to configure NATS TLS: %w", tlsErr)
		}
		natsCfg.TLSConfig = tlsCfg
		log.Info("NATS TLS enabled", "ca_file", cfg.NATS.TLS.CAFile, "cert_file", cfg.NATS.TLS.CertFile)
	}

	nc, err := nats.NewClient(natsCfg, log.Base())
	if err != nil {
		return nil, fmt.Errorf("failed to connect to NATS: %w", err)
	}
	// IsConnected is set after NewClient resolves the URL list; we treat any
	// nats.NewClient success as connected here to match the previous
	// behavior (the previous code logged "NATS connected" immediately after
	// the constructor returned).
	_ = ctx
	log.Info("NATS connected", "url", cfg.NATS.URL)
	return nc, nil
}

// initPKI sets up the project-wide PKI manager (when TLS is enabled and the
// mode is not agent) and auto-configures NATS mTLS from the generated certs
// when the operator hasn't explicitly configured them.
func initPKI(cfg *Config, log *logger.Logger) (*crypto.PKIManager, error) {
	if !cfg.Server.TLS.Enabled || cfg.Mode == "agent" {
		return nil, nil
	}

	pkiDataDir := cfg.Server.TLS.DataDir
	if pkiDataDir == "" {
		pkiDataDir = cfg.Storage.Path + "/pki"
	}

	pkiMgr, err := crypto.NewPKIManager(pkiDataDir)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize PKI: %w", err)
	}
	log.Info("PKI initialized", "data_dir", pkiDataDir)

	natsCertPath, natsKeyPath, natsErr := pkiMgr.EnsureNATSServerCert("nats", "localhost")
	if natsErr != nil {
		return nil, fmt.Errorf("failed to ensure NATS server cert: %w", natsErr)
	}
	log.Info("NATS server certificate ready",
		"cert", natsCertPath,
		"key", natsKeyPath,
		"ca", pkiMgr.CACertPath(),
	)

	if !cfg.NATS.TLS.Enabled && (cfg.Mode == "master" || cfg.NATS.URL != "") {
		masterCertPath, masterKeyPath, masterErr := pkiMgr.EnsureMasterNATSClientCert()
		if masterErr != nil {
			return nil, fmt.Errorf("failed to ensure master NATS client cert: %w", masterErr)
		}

		cfg.NATS.TLS.Enabled = true
		cfg.NATS.TLS.CertFile = masterCertPath
		cfg.NATS.TLS.KeyFile = masterKeyPath
		cfg.NATS.TLS.CAFile = pkiMgr.CACertPath()
		log.Info("NATS mTLS auto-configured from PKI",
			"cert", masterCertPath,
			"ca", pkiMgr.CACertPath(),
		)
	}

	return pkiMgr, nil
}
