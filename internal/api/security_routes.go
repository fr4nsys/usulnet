// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// security_routes.go
// Este archivo contiene las rutas del Departamento F (Security Scanner)
// Añadir al router.go existente

package api

/*
INSTRUCCIONES:

1. Añadir SecurityHandler a la estructura Handlers en router.go:

type Handlers struct {
    System    *handlers.SystemHandler
    WebSocket *handlers.WebSocketHandler
    Security  *handlers.SecurityHandler  // <-- Añadir esta línea
    // ... otros handlers
}

2. Reemplazar el bloque de rutas /security en NewRouter() con el siguiente código:
*/

// SecurityRoutes configura todas las rutas del scanner de seguridad.
// Reemplazar el bloque r.Route("/security", ...) en router.go con este contenido:

/*
// -----------------------------------------------------------------
// Security routes (Department F)
// -----------------------------------------------------------------
r.Route("/security", func(r chi.Router) {
    // === Scan endpoints ===

    // List all scans with filtering
    // GET /api/v1/security/scans?host_id=&container_id=&min_score=&max_score=&grade=&since=&limit=&offset=
    r.With(middleware.RequireViewer).Get("/scans", h.Security.ListScans)

    // Get specific scan details with issues
    // GET /api/v1/security/scans/{id}
    r.With(middleware.RequireViewer).Get("/scans/{id}", h.Security.GetScan)

    // Delete a scan
    // DELETE /api/v1/security/scans/{id}
    r.With(middleware.RequireAdmin).Delete("/scans/{id}", h.Security.DeleteScan)

    // Scan a single container
    // POST /api/v1/security/scans
    // Body: { "container_id": "...", "host_id": "...", "include_cve": true }
    r.With(middleware.RequireOperator).Post("/scans", h.Security.ScanContainer)

    // Scan all containers on a host
    // POST /api/v1/security/scans/all
    // Body: { "host_id": "...", "include_cve": false }
    r.With(middleware.RequireOperator).Post("/scans/all", h.Security.ScanAllContainers)

    // === Issue endpoints ===

    // List issues with filtering
    // GET /api/v1/security/issues?host_id=&container_id=&scan_id=&severity=&category=&status=&check_id=&limit=&offset=
    r.With(middleware.RequireViewer).Get("/issues", h.Security.ListIssues)

    // Get specific issue details
    // GET /api/v1/security/issues/{id}
    r.With(middleware.RequireViewer).Get("/issues/{id}", h.Security.GetIssue)

    // Update issue status (acknowledge, resolve, ignore)
    // PUT /api/v1/security/issues/{id}/status
    // Body: { "status": "acknowledged|resolved|ignored|false_positive", "user_id": "...", "comment": "..." }
    r.With(middleware.RequireOperator).Put("/issues/{id}/status", h.Security.UpdateIssueStatus)

    // === Summary and reporting ===

    // Get security summary/dashboard
    // GET /api/v1/security/summary?host_id=
    r.With(middleware.RequireViewer).Get("/summary", h.Security.GetSecuritySummary)

    // Generate security report
    // GET /api/v1/security/report?host_id=&format=json|html|markdown|text&details=true&trends=true&min_severity=
    r.With(middleware.RequireViewer).Get("/report", h.Security.GenerateReport)
})

// -----------------------------------------------------------------
// Container security sub-routes
// -----------------------------------------------------------------
// Añadir dentro de r.Route("/containers", ...) :

r.Route("/containers", func(r chi.Router) {
    // ... rutas existentes de containers ...

    // Security scans for specific container
    // GET /api/v1/containers/{id}/security/scans - Scan history
    r.With(middleware.RequireViewer).Get("/{id}/security/scans", h.Security.GetContainerScans)

    // GET /api/v1/containers/{id}/security/latest - Most recent scan
    r.With(middleware.RequireViewer).Get("/{id}/security/latest", h.Security.GetLatestScan)

    // GET /api/v1/containers/{id}/security/history - Score history over time
    r.With(middleware.RequireViewer).Get("/{id}/security/history", h.Security.GetScoreHistory)
})
*/

// ============================================================================
// Endpoint Summary
// ============================================================================
//
// SCANS:
// POST   /api/v1/security/scans                    - Scan container
// POST   /api/v1/security/scans/all                - Scan all containers
// GET    /api/v1/security/scans                    - List scans
// GET    /api/v1/security/scans/{id}               - Get scan details
// DELETE /api/v1/security/scans/{id}               - Delete scan
//
// ISSUES:
// GET    /api/v1/security/issues                   - List issues
// GET    /api/v1/security/issues/{id}              - Get issue details
// PUT    /api/v1/security/issues/{id}/status       - Update issue status
//
// SUMMARY:
// GET    /api/v1/security/summary                  - Security dashboard
// GET    /api/v1/security/report                   - Generate report
//
// CONTAINER SUB-ROUTES:
// GET    /api/v1/containers/{id}/security/scans    - Container scan history
// GET    /api/v1/containers/{id}/security/latest   - Latest scan
// GET    /api/v1/containers/{id}/security/history  - Score history
//
// ============================================================================
