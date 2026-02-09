// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package api

import (
	"github.com/go-chi/chi/v5"

	"github.com/fr4nsys/usulnet/internal/api/handlers"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/scheduler"
)

// RegisterJobRoutes registers job-related routes
func RegisterJobRoutes(r chi.Router, sched *scheduler.Scheduler, log *logger.Logger) {
	jobsHandler := handlers.NewJobsHandler(sched, log)

	r.Route("/jobs", func(r chi.Router) {
		r.Mount("/", jobsHandler.Routes())
	})
}

// JobRoutes returns a router with all job endpoints
// 
// Endpoints:
//   GET    /api/jobs                              - List jobs with filtering
//   POST   /api/jobs                              - Create and enqueue a new job
//   GET    /api/jobs/stats                        - Get job statistics
//   GET    /api/jobs/queue-stats                  - Get Redis queue statistics
//   GET    /api/jobs/pool-stats                   - Get worker pool statistics
//   GET    /api/jobs/{jobID}                      - Get job details
//   DELETE /api/jobs/{jobID}                      - Cancel a job
//
//   GET    /api/jobs/scheduled                    - List scheduled jobs
//   POST   /api/jobs/scheduled                    - Create a scheduled job
//   GET    /api/jobs/scheduled/{scheduledJobID}  - Get scheduled job details
//   PUT    /api/jobs/scheduled/{scheduledJobID}  - Update a scheduled job
//   DELETE /api/jobs/scheduled/{scheduledJobID}  - Delete a scheduled job
//   POST   /api/jobs/scheduled/{scheduledJobID}/run - Trigger scheduled job now
func JobRoutes(sched *scheduler.Scheduler, log *logger.Logger) chi.Router {
	jobsHandler := handlers.NewJobsHandler(sched, log)
	return jobsHandler.Routes()
}
