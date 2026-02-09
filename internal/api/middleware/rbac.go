// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package middleware

import (
	"net/http"

	apierrors "github.com/fr4nsys/usulnet/internal/api/errors"
)

// Role represents a user role in the system.
type Role string

const (
	// RoleAdmin has full access to all resources and operations.
	RoleAdmin Role = "admin"

	// RoleOperator can manage containers, images, volumes, networks, and stacks.
	// Cannot manage users, settings, or hosts.
	RoleOperator Role = "operator"

	// RoleViewer has read-only access to all resources.
	RoleViewer Role = "viewer"
)

// roleHierarchy defines the permission level of each role.
// Higher number = more permissions.
var roleHierarchy = map[Role]int{
	RoleViewer:   1,
	RoleOperator: 2,
	RoleAdmin:    3,
}

// HasMinRole checks if the user's role meets the minimum required role.
func HasMinRole(userRole string, minRole Role) bool {
	userLevel := roleHierarchy[Role(userRole)]
	requiredLevel := roleHierarchy[minRole]
	return userLevel >= requiredLevel
}

// IsAdmin checks if the user is an admin.
func IsAdmin(userRole string) bool {
	return Role(userRole) == RoleAdmin
}

// RequireRole returns a middleware that requires a minimum role.
func RequireRole(minRole Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetUserFromContext(r.Context())
			if claims == nil {
				requestID := GetRequestID(r.Context())
				apierrors.WriteErrorWithRequestID(w, apierrors.Unauthorized(""), requestID)
				return
			}

			if !HasMinRole(claims.Role, minRole) {
				requestID := GetRequestID(r.Context())
				apierrors.WriteErrorWithRequestID(w, apierrors.Forbidden("Insufficient permissions"), requestID)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAdmin is a shortcut middleware that requires admin role.
func RequireAdmin(next http.Handler) http.Handler {
	return RequireRole(RoleAdmin)(next)
}

// RequireOperator is a shortcut middleware that requires operator role or higher.
func RequireOperator(next http.Handler) http.Handler {
	return RequireRole(RoleOperator)(next)
}

// RequireViewer is a shortcut middleware that requires viewer role or higher.
// Essentially just checks that the user is authenticated.
func RequireViewer(next http.Handler) http.Handler {
	return RequireRole(RoleViewer)(next)
}

// ============================================================================
// Permission-based access control
// ============================================================================

// Permission represents a specific permission.
type Permission string

const (
	// Container permissions
	PermContainerView    Permission = "container:view"
	PermContainerCreate  Permission = "container:create"
	PermContainerStart   Permission = "container:start"
	PermContainerStop    Permission = "container:stop"
	PermContainerRestart Permission = "container:restart"
	PermContainerRemove  Permission = "container:remove"
	PermContainerExec    Permission = "container:exec"
	PermContainerLogs    Permission = "container:logs"

	// Image permissions
	PermImageView   Permission = "image:view"
	PermImagePull   Permission = "image:pull"
	PermImageRemove Permission = "image:remove"
	PermImageBuild  Permission = "image:build"

	// Volume permissions
	PermVolumeView   Permission = "volume:view"
	PermVolumeCreate Permission = "volume:create"
	PermVolumeRemove Permission = "volume:remove"

	// Network permissions
	PermNetworkView   Permission = "network:view"
	PermNetworkCreate Permission = "network:create"
	PermNetworkRemove Permission = "network:remove"

	// Stack permissions
	PermStackView   Permission = "stack:view"
	PermStackDeploy Permission = "stack:deploy"
	PermStackUpdate Permission = "stack:update"
	PermStackRemove Permission = "stack:remove"

	// Host permissions
	PermHostView   Permission = "host:view"
	PermHostCreate Permission = "host:create"
	PermHostUpdate Permission = "host:update"
	PermHostRemove Permission = "host:remove"

	// User management permissions
	PermUserView   Permission = "user:view"
	PermUserCreate Permission = "user:create"
	PermUserUpdate Permission = "user:update"
	PermUserRemove Permission = "user:remove"

	// Settings permissions
	PermSettingsView   Permission = "settings:view"
	PermSettingsUpdate Permission = "settings:update"

	// Backup permissions
	PermBackupCreate  Permission = "backup:create"
	PermBackupRestore Permission = "backup:restore"
	PermBackupView    Permission = "backup:view"

	// Security permissions
	PermSecurityScan Permission = "security:scan"
	PermSecurityView Permission = "security:view"

	// Config permissions
	PermConfigView   Permission = "config:view"
	PermConfigCreate Permission = "config:create"
	PermConfigUpdate Permission = "config:update"
	PermConfigRemove Permission = "config:remove"
)

// rolePermissions defines which permissions each role has.
var rolePermissions = map[Role][]Permission{
	RoleViewer: {
		// Read-only access
		PermContainerView,
		PermContainerLogs,
		PermImageView,
		PermVolumeView,
		PermNetworkView,
		PermStackView,
		PermHostView,
		PermBackupView,
		PermSecurityView,
		PermConfigView,
	},
	RoleOperator: {
		// All viewer permissions plus management
		PermContainerView,
		PermContainerCreate,
		PermContainerStart,
		PermContainerStop,
		PermContainerRestart,
		PermContainerRemove,
		PermContainerExec,
		PermContainerLogs,
		PermImageView,
		PermImagePull,
		PermImageRemove,
		PermVolumeView,
		PermVolumeCreate,
		PermVolumeRemove,
		PermNetworkView,
		PermNetworkCreate,
		PermNetworkRemove,
		PermStackView,
		PermStackDeploy,
		PermStackUpdate,
		PermStackRemove,
		PermHostView,
		PermBackupCreate,
		PermBackupView,
		PermSecurityScan,
		PermSecurityView,
		PermConfigView,
		PermConfigCreate,
		PermConfigUpdate,
		PermConfigRemove,
	},
	RoleAdmin: {
		// All permissions
		PermContainerView,
		PermContainerCreate,
		PermContainerStart,
		PermContainerStop,
		PermContainerRestart,
		PermContainerRemove,
		PermContainerExec,
		PermContainerLogs,
		PermImageView,
		PermImagePull,
		PermImageRemove,
		PermImageBuild,
		PermVolumeView,
		PermVolumeCreate,
		PermVolumeRemove,
		PermNetworkView,
		PermNetworkCreate,
		PermNetworkRemove,
		PermStackView,
		PermStackDeploy,
		PermStackUpdate,
		PermStackRemove,
		PermHostView,
		PermHostCreate,
		PermHostUpdate,
		PermHostRemove,
		PermUserView,
		PermUserCreate,
		PermUserUpdate,
		PermUserRemove,
		PermSettingsView,
		PermSettingsUpdate,
		PermBackupCreate,
		PermBackupRestore,
		PermBackupView,
		PermSecurityScan,
		PermSecurityView,
		PermConfigView,
		PermConfigCreate,
		PermConfigUpdate,
		PermConfigRemove,
	},
}

// permissionCache caches permission lookups for performance.
var permissionCache = make(map[Role]map[Permission]bool)

func init() {
	// Build permission cache at startup
	for role, perms := range rolePermissions {
		permissionCache[role] = make(map[Permission]bool)
		for _, perm := range perms {
			permissionCache[role][perm] = true
		}
	}
}

// HasPermission checks if a role has a specific permission.
func HasPermission(userRole string, perm Permission) bool {
	if perms, ok := permissionCache[Role(userRole)]; ok {
		return perms[perm]
	}
	return false
}

// RequirePermission returns a middleware that requires a specific permission.
func RequirePermission(perm Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetUserFromContext(r.Context())
			if claims == nil {
				requestID := GetRequestID(r.Context())
				apierrors.WriteErrorWithRequestID(w, apierrors.Unauthorized(""), requestID)
				return
			}

			if !HasPermission(claims.Role, perm) {
				requestID := GetRequestID(r.Context())
				apierrors.WriteErrorWithRequestID(w, apierrors.Forbidden("Missing permission: "+string(perm)), requestID)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyPermission returns a middleware that requires any of the specified permissions.
func RequireAnyPermission(perms ...Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetUserFromContext(r.Context())
			if claims == nil {
				requestID := GetRequestID(r.Context())
				apierrors.WriteErrorWithRequestID(w, apierrors.Unauthorized(""), requestID)
				return
			}

			for _, perm := range perms {
				if HasPermission(claims.Role, perm) {
					next.ServeHTTP(w, r)
					return
				}
			}

			requestID := GetRequestID(r.Context())
			apierrors.WriteErrorWithRequestID(w, apierrors.Forbidden("Insufficient permissions"), requestID)
		})
	}
}

// RequireAllPermissions returns a middleware that requires all of the specified permissions.
func RequireAllPermissions(perms ...Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetUserFromContext(r.Context())
			if claims == nil {
				requestID := GetRequestID(r.Context())
				apierrors.WriteErrorWithRequestID(w, apierrors.Unauthorized(""), requestID)
				return
			}

			for _, perm := range perms {
				if !HasPermission(claims.Role, perm) {
					requestID := GetRequestID(r.Context())
					apierrors.WriteErrorWithRequestID(w, apierrors.Forbidden("Missing permission: "+string(perm)), requestID)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ============================================================================
// Team-based access (for multi-tenant scenarios)
// ============================================================================

// TeamAccessChecker is a function that checks if a user has access to a team.
type TeamAccessChecker func(userID string, userTeams []string, resourceTeam string) bool

// RequireTeamAccess returns a middleware that checks team-based access.
// The teamExtractor function extracts the team from the request (e.g., from URL params).
func RequireTeamAccess(teamExtractor func(*http.Request) string, checker TeamAccessChecker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetUserFromContext(r.Context())
			if claims == nil {
				requestID := GetRequestID(r.Context())
				apierrors.WriteErrorWithRequestID(w, apierrors.Unauthorized(""), requestID)
				return
			}

			// Admins bypass team checks
			if IsAdmin(claims.Role) {
				next.ServeHTTP(w, r)
				return
			}

			resourceTeam := teamExtractor(r)
			if resourceTeam == "" {
				// No team restriction
				next.ServeHTTP(w, r)
				return
			}

			if !checker(claims.UserID, claims.Teams, resourceTeam) {
				requestID := GetRequestID(r.Context())
				apierrors.WriteErrorWithRequestID(w, apierrors.Forbidden("No access to this team's resources"), requestID)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// DefaultTeamAccessChecker checks if user is a member of the resource's team.
func DefaultTeamAccessChecker(userID string, userTeams []string, resourceTeam string) bool {
	for _, team := range userTeams {
		if team == resourceTeam {
			return true
		}
	}
	return false
}
