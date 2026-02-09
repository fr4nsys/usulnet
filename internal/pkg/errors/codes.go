// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package errors

// General error codes
const (
	CodeInternal     = "INTERNAL_ERROR"
	CodeNotFound     = "NOT_FOUND"
	CodeBadRequest   = "BAD_REQUEST"
	CodeInvalidInput = "INVALID_INPUT"
	CodeUnauthorized = "UNAUTHORIZED"
	CodeForbidden    = "FORBIDDEN"
	CodeConflict     = "CONFLICT"
	CodeTimeout      = "TIMEOUT"
	CodeRateLimited  = "RATE_LIMITED"
)

// Authentication error codes
const (
	CodeInvalidCredentials = "INVALID_CREDENTIALS"
	CodeTokenExpired       = "TOKEN_EXPIRED"
	CodeTokenInvalid       = "TOKEN_INVALID"
	CodeTokenRevoked       = "TOKEN_REVOKED"
	CodeAccountLocked      = "ACCOUNT_LOCKED"
	CodeAccountDisabled    = "ACCOUNT_DISABLED"
	CodeSessionExpired     = "SESSION_EXPIRED"
	CodeAPIKeyInvalid      = "API_KEY_INVALID"
	CodeAPIKeyExpired      = "API_KEY_EXPIRED"
)

// Authorization error codes
const (
	CodeInsufficientPermissions = "INSUFFICIENT_PERMISSIONS"
	CodeResourceAccessDenied    = "RESOURCE_ACCESS_DENIED"
	CodeOperationNotAllowed     = "OPERATION_NOT_ALLOWED"
)

// Validation error codes
const (
	CodeValidationFailed = "VALIDATION_FAILED"
	CodeInvalidFormat    = "INVALID_FORMAT"
	CodeMissingField     = "MISSING_FIELD"
	CodeInvalidValue     = "INVALID_VALUE"
)

// Docker error codes
const (
	CodeDockerConnection    = "DOCKER_CONNECTION_ERROR"
	CodeDockerTimeout       = "DOCKER_TIMEOUT"
	CodeContainerNotFound   = "CONTAINER_NOT_FOUND"
	CodeContainerNotRunning = "CONTAINER_NOT_RUNNING"
	CodeImageNotFound       = "IMAGE_NOT_FOUND"
	CodeImagePullFailed     = "IMAGE_PULL_FAILED"
	CodeVolumeNotFound      = "VOLUME_NOT_FOUND"
	CodeNetworkNotFound     = "NETWORK_NOT_FOUND"
	CodeComposeInvalid      = "COMPOSE_INVALID"
	CodeComposeFailed       = "COMPOSE_FAILED"
)

// Host error codes
const (
	CodeHostNotFound     = "HOST_NOT_FOUND"
	CodeHostOffline      = "HOST_OFFLINE"
	CodeHostUnreachable  = "HOST_UNREACHABLE"
	CodeAgentNotFound    = "AGENT_NOT_FOUND"
	CodeAgentDisconnected = "AGENT_DISCONNECTED"
)

// Backup error codes
const (
	CodeBackupNotFound   = "BACKUP_NOT_FOUND"
	CodeBackupFailed     = "BACKUP_FAILED"
	CodeBackupCorrupted  = "BACKUP_CORRUPTED"
	CodeRestoreFailed    = "RESTORE_FAILED"
	CodeStorageFull      = "STORAGE_FULL"
	CodeStorageError     = "STORAGE_ERROR"
)

// Update error codes
const (
	CodeUpdateNotAvailable = "UPDATE_NOT_AVAILABLE"
	CodeUpdateFailed       = "UPDATE_FAILED"
	CodeRollbackFailed     = "ROLLBACK_FAILED"
	CodeHealthCheckFailed  = "HEALTH_CHECK_FAILED"
)

// Security error codes
const (
	CodeSecurityScanFailed = "SECURITY_SCAN_FAILED"
	CodeTrivyError         = "TRIVY_ERROR"
	CodeEncryptionFailed   = "ENCRYPTION_FAILED"
	CodeDecryptionFailed   = "DECRYPTION_FAILED"
)

// Configuration error codes
const (
	CodeConfigNotFound   = "CONFIG_NOT_FOUND"
	CodeConfigInvalid    = "CONFIG_INVALID"
	CodeConfigSyncFailed = "CONFIG_SYNC_FAILED"
	CodeSecretNotFound   = "SECRET_NOT_FOUND"
)

// Database error codes
const (
	CodeDatabaseError      = "DATABASE_ERROR"
	CodeDatabaseConnection = "DATABASE_CONNECTION_ERROR"
	CodeDatabaseTimeout    = "DATABASE_TIMEOUT"
	CodeConstraintViolation = "CONSTRAINT_VIOLATION"
	CodeMigrationFailed    = "MIGRATION_FAILED"
)

// License error codes
const (
	CodeLicenseInvalid  = "LICENSE_INVALID"
	CodeLicenseExpired  = "LICENSE_EXPIRED"
	CodeLicenseNotFound = "LICENSE_NOT_FOUND"
	CodeFeatureDisabled = "FEATURE_DISABLED"
	CodeLimitExceeded   = "LIMIT_EXCEEDED"
)

// NPM integration error codes
const (
	CodeNPMNotConfigured  = "NPM_NOT_CONFIGURED"
	CodeNPMConnectionFailed = "NPM_CONNECTION_FAILED"
	CodeNPMProxyNotFound  = "NPM_PROXY_NOT_FOUND"
	CodeNPMSyncFailed     = "NPM_SYNC_FAILED"
)

// Notification error codes
const (
	CodeNotificationFailed     = "NOTIFICATION_FAILED"
	CodeWebhookFailed          = "WEBHOOK_FAILED"
	CodeEmailFailed            = "EMAIL_FAILED"
	CodeSlackNotificationFailed = "SLACK_NOTIFICATION_FAILED"
)

// Job error codes
const (
	CodeJobNotFound  = "JOB_NOT_FOUND"
	CodeJobFailed    = "JOB_FAILED"
	CodeJobCancelled = "JOB_CANCELLED"
	CodeJobTimeout   = "JOB_TIMEOUT"
)

// Compatibility codes (aliases for migration)
const (
	CodeValidation   = CodeValidationFailed
	CodeDocker       = CodeDockerConnection
	CodeNotSupported = "NOT_SUPPORTED"
	CodeExternal     = "EXTERNAL_ERROR"
)

// Additional compatibility codes
const (
	CodeResourceExhausted = "RESOURCE_EXHAUSTED"
	CodeDatabase          = CodeDatabaseError
)
