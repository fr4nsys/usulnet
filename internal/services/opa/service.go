// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package opa

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ============================================================================
// Repository interface
// ============================================================================

// Repository defines the persistence operations required by the OPA service.
type Repository interface {
	CreatePolicy(ctx context.Context, p *models.OPAPolicy) error
	GetPolicy(ctx context.Context, id uuid.UUID) (*models.OPAPolicy, error)
	GetPolicyByName(ctx context.Context, name string) (*models.OPAPolicy, error)
	ListPolicies(ctx context.Context, category string) ([]*models.OPAPolicy, error)
	UpdatePolicy(ctx context.Context, p *models.OPAPolicy) error
	DeletePolicy(ctx context.Context, id uuid.UUID) error
	TogglePolicy(ctx context.Context, id uuid.UUID, enabled bool) error
	IncrementEvaluation(ctx context.Context, policyID uuid.UUID, isViolation bool) error
	SaveResult(ctx context.Context, result *models.OPAEvaluationResult) error
	ListResults(ctx context.Context, policyID uuid.UUID, limit int) ([]*models.OPAEvaluationResult, error)
	GetResultsByTarget(ctx context.Context, targetType, targetID string) ([]*models.OPAEvaluationResult, error)
}

// ============================================================================
// Rule-based policy engine types
// ============================================================================

// RuleDefinition is the JSON structure stored in rego_code that defines
// the policy rules. Each rule inspects a single field in the input data.
type RuleDefinition struct {
	Rules []Rule `json:"rules"`
}

// Rule describes a single condition to evaluate against the input data.
//
//	Field   - dot-notation path into the input map (e.g. "config.user")
//	Op      - operator: eq, neq, contains, not_contains, gt, lt, exists, not_exists, matches
//	Value   - the comparison value (type depends on operator)
//	Message - human-readable violation message shown when the rule triggers
type Rule struct {
	Field   string      `json:"field"`
	Op      string      `json:"op"`
	Value   interface{} `json:"value"`
	Message string      `json:"message"`
}

// EvaluationResult is the service-level result of evaluating one or more
// policies against an input payload.
type EvaluationResult struct {
	PolicyID   uuid.UUID `json:"policy_id"`
	PolicyName string    `json:"policy_name"`
	Decision   string    `json:"decision"` // "allow" or "deny"
	Violations []string  `json:"violations,omitempty"`
	Severity   string    `json:"severity"`
}

// ============================================================================
// Configuration
// ============================================================================

// Config holds configuration for the OPA evaluation service.
type Config struct {
	// Enabled controls whether policy evaluation is active.
	Enabled bool

	// DefaultAction is the decision when no policies match ("allow" or "deny").
	DefaultAction string

	// EvaluationTimeout limits the wall-clock time for a single evaluation run.
	EvaluationTimeout time.Duration
}

// DefaultConfig returns sensible defaults for the OPA service.
func DefaultConfig() Config {
	return Config{
		Enabled:           true,
		DefaultAction:     "allow",
		EvaluationTimeout: 5 * time.Second,
	}
}

// ============================================================================
// Service
// ============================================================================

// Service provides OPA-style policy evaluation using a lightweight, in-process
// rule engine. Policies are defined as JSON rule sets and cached in memory
// after first compilation.
type Service struct {
	repo   Repository
	config Config
	logger *logger.Logger

	// compiledPolicies caches parsed rule definitions keyed by policy ID.
	mu               sync.RWMutex
	compiledPolicies map[uuid.UUID]*RuleDefinition
}

// NewService creates a new OPA evaluation service.
func NewService(repo Repository, config Config, log *logger.Logger) *Service {
	if log == nil {
		log = logger.Nop()
	}

	return &Service{
		repo:             repo,
		config:           config,
		logger:           log.Named("opa"),
		compiledPolicies: make(map[uuid.UUID]*RuleDefinition),
	}
}

// ============================================================================
// Public query methods
// ============================================================================

// ListPolicies returns all OPA policies, optionally filtered by category.
func (s *Service) ListPolicies(ctx context.Context, category string) ([]*models.OPAPolicy, error) {
	return s.repo.ListPolicies(ctx, category)
}

// ============================================================================
// Public evaluation methods
// ============================================================================

// EvaluateContainer evaluates all enabled container-related policies against
// the provided container data and returns a result per policy.
func (s *Service) EvaluateContainer(ctx context.Context, containerData map[string]interface{}) ([]*EvaluationResult, error) {
	return s.evaluateByCategories(ctx, containerData, "container", []string{
		models.OPACategoryAdmission,
		models.OPACategoryRuntime,
		models.OPACategoryNetwork,
		models.OPACategoryGeneral,
	})
}

// EvaluateImage evaluates all enabled image-related policies against the
// provided image data and returns a result per policy.
func (s *Service) EvaluateImage(ctx context.Context, imageData map[string]interface{}) ([]*EvaluationResult, error) {
	return s.evaluateByCategories(ctx, imageData, "image", []string{
		models.OPACategoryImage,
		models.OPACategoryGeneral,
	})
}

// EvaluatePolicy evaluates a single policy (by ID) against the provided input.
func (s *Service) EvaluatePolicy(ctx context.Context, policyID uuid.UUID, input map[string]interface{}) (*EvaluationResult, error) {
	if !s.config.Enabled {
		return &EvaluationResult{
			PolicyID: policyID,
			Decision: "allow",
		}, nil
	}

	policy, err := s.repo.GetPolicy(ctx, policyID)
	if err != nil {
		return nil, fmt.Errorf("get policy %s: %w", policyID, err)
	}

	result := s.evaluateSinglePolicy(policy, input)

	// Persist result asynchronously-safe: we do it inline for simplicity.
	s.persistResult(ctx, policy, result, input, "")
	return result, nil
}

// ============================================================================
// Default policy seeding
// ============================================================================

// SeedDefaultPolicies creates the built-in container security policies if
// they do not already exist (matched by name). Existing policies are not
// overwritten so that user customisations are preserved.
func (s *Service) SeedDefaultPolicies(ctx context.Context) error {
	defaults := defaultPolicies()

	for _, p := range defaults {
		existing, _ := s.repo.GetPolicyByName(ctx, p.Name)
		if existing != nil {
			continue
		}
		if err := s.repo.CreatePolicy(ctx, p); err != nil {
			s.logger.Warn("Failed to seed default policy",
				"name", p.Name,
				"error", err)
			continue
		}
		s.logger.Info("Seeded default OPA policy", "name", p.Name)
	}

	return nil
}

// ============================================================================
// Internal evaluation logic
// ============================================================================

// evaluateByCategories fetches enabled policies for the given categories and
// evaluates them against the input data.
func (s *Service) evaluateByCategories(ctx context.Context, input map[string]interface{}, targetType string, categories []string) ([]*EvaluationResult, error) {
	if !s.config.Enabled {
		return nil, nil
	}

	// Apply evaluation timeout.
	evalCtx, cancel := context.WithTimeout(ctx, s.config.EvaluationTimeout)
	defer cancel()

	var allPolicies []*models.OPAPolicy
	for _, cat := range categories {
		policies, err := s.repo.ListPolicies(evalCtx, cat)
		if err != nil {
			return nil, fmt.Errorf("list policies for category %s: %w", cat, err)
		}
		allPolicies = append(allPolicies, policies...)
	}

	// Deduplicate by ID (a policy can only appear once even if categories overlap).
	seen := make(map[uuid.UUID]bool, len(allPolicies))
	var unique []*models.OPAPolicy
	for _, p := range allPolicies {
		if seen[p.ID] {
			continue
		}
		seen[p.ID] = true
		unique = append(unique, p)
	}

	// Derive a target ID from input for result persistence.
	targetID := extractStringField(input, "id")
	targetName := extractStringField(input, "name")

	var results []*EvaluationResult
	for _, policy := range unique {
		if !policy.IsEnabled {
			continue
		}

		result := s.evaluateSinglePolicy(policy, input)
		results = append(results, result)

		s.persistResult(evalCtx, policy, result, input, targetType)

		// Also persist the DB-level evaluation result.
		s.saveDBResult(evalCtx, policy, result, targetType, targetID, targetName, input)
	}

	return results, nil
}

// evaluateSinglePolicy parses the policy's rule definition (with caching) and
// evaluates every rule against the input data.
func (s *Service) evaluateSinglePolicy(policy *models.OPAPolicy, input map[string]interface{}) *EvaluationResult {
	result := &EvaluationResult{
		PolicyID:   policy.ID,
		PolicyName: policy.Name,
		Decision:   "allow",
		Severity:   policy.Severity,
	}

	ruleDef, err := s.compilePolicy(policy)
	if err != nil {
		s.logger.Warn("Failed to compile policy rules",
			"policy", policy.Name,
			"error", err)
		// On parse failure, fall back to the configured default action.
		result.Decision = s.config.DefaultAction
		return result
	}

	for _, rule := range ruleDef.Rules {
		if violated := evaluateRule(rule, input); violated {
			result.Violations = append(result.Violations, rule.Message)
		}
	}

	if len(result.Violations) > 0 {
		result.Decision = "deny"
	}

	return result
}

// compilePolicy returns a cached or freshly-parsed RuleDefinition for the
// given policy.
func (s *Service) compilePolicy(policy *models.OPAPolicy) (*RuleDefinition, error) {
	s.mu.RLock()
	cached, ok := s.compiledPolicies[policy.ID]
	s.mu.RUnlock()
	if ok {
		return cached, nil
	}

	var rd RuleDefinition
	if err := json.Unmarshal([]byte(policy.RegoCode), &rd); err != nil {
		return nil, fmt.Errorf("unmarshal rule definition for %s: %w", policy.Name, err)
	}

	s.mu.Lock()
	s.compiledPolicies[policy.ID] = &rd
	s.mu.Unlock()

	return &rd, nil
}

// InvalidatePolicyCache removes a policy from the compiled cache so that
// it will be re-parsed on the next evaluation.
func (s *Service) InvalidatePolicyCache(policyID uuid.UUID) {
	s.mu.Lock()
	delete(s.compiledPolicies, policyID)
	s.mu.Unlock()
}

// InvalidateAllCaches clears the entire compiled policy cache.
func (s *Service) InvalidateAllCaches() {
	s.mu.Lock()
	s.compiledPolicies = make(map[uuid.UUID]*RuleDefinition)
	s.mu.Unlock()
}

// persistResult increments the repo-level evaluation counters.
func (s *Service) persistResult(ctx context.Context, policy *models.OPAPolicy, result *EvaluationResult, _ map[string]interface{}, _ string) {
	isViolation := result.Decision == "deny"
	if err := s.repo.IncrementEvaluation(ctx, policy.ID, isViolation); err != nil {
		s.logger.Warn("Failed to increment evaluation counter",
			"policy", policy.Name,
			"error", err)
	}
}

// saveDBResult persists a full OPAEvaluationResult row.
func (s *Service) saveDBResult(ctx context.Context, policy *models.OPAPolicy, result *EvaluationResult, targetType, targetID, targetName string, input map[string]interface{}) {
	violationsJSON, _ := json.Marshal(result.Violations)
	inputJSON, _ := json.Marshal(input)
	hash := fmt.Sprintf("%x", sha256.Sum256(inputJSON))

	dbResult := &models.OPAEvaluationResult{
		PolicyID:    policy.ID,
		TargetType:  targetType,
		TargetID:    targetID,
		TargetName:  targetName,
		Decision:    result.Decision == "allow",
		Violations:  violationsJSON,
		InputHash:   hash,
		EvaluatedAt: time.Now(),
	}

	if err := s.repo.SaveResult(ctx, dbResult); err != nil {
		s.logger.Warn("Failed to save evaluation result",
			"policy", policy.Name,
			"error", err)
	}
}

// ============================================================================
// Rule evaluation engine
// ============================================================================

// evaluateRule checks whether a single rule is violated by the input data.
// Returns true when the rule condition IS violated.
func evaluateRule(rule Rule, input map[string]interface{}) bool {
	fieldVal, exists := resolveField(input, rule.Field)

	switch rule.Op {
	case "exists":
		return !exists
	case "not_exists":
		return exists
	case "eq":
		return !exists || !valuesEqual(fieldVal, rule.Value)
	case "neq":
		return exists && valuesEqual(fieldVal, rule.Value)
	case "contains":
		return !exists || !valueContains(fieldVal, rule.Value)
	case "not_contains":
		return exists && valueContains(fieldVal, rule.Value)
	case "gt":
		return !exists || !valueGT(fieldVal, rule.Value)
	case "lt":
		return !exists || !valueLT(fieldVal, rule.Value)
	case "matches":
		return !exists || !valueMatches(fieldVal, rule.Value)
	default:
		return false
	}
}

// resolveField traverses a dot-notation path (e.g. "config.user") into a
// nested map and returns the leaf value plus a boolean indicating existence.
func resolveField(data map[string]interface{}, path string) (interface{}, bool) {
	parts := strings.Split(path, ".")
	var current interface{} = data

	for _, part := range parts {
		switch m := current.(type) {
		case map[string]interface{}:
			val, ok := m[part]
			if !ok {
				return nil, false
			}
			current = val
		default:
			return nil, false
		}
	}

	return current, true
}

// valuesEqual compares two interface values for equality, handling common
// JSON-decoded types (string, bool, float64).
func valuesEqual(a, b interface{}) bool {
	// Normalise numeric types coming from JSON (always float64).
	af := toFloat64(a)
	bf := toFloat64(b)
	if af != nil && bf != nil {
		return *af == *bf
	}

	// Boolean comparison.
	ab, aIsBool := a.(bool)
	bb, bIsBool := toBool(b)
	if aIsBool && bIsBool {
		return ab == bb
	}

	// String comparison.
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

// valueContains checks whether a contains b:
//   - string in string
//   - element in slice
func valueContains(a, b interface{}) bool {
	// String substring check.
	if as, ok := a.(string); ok {
		bs := fmt.Sprintf("%v", b)
		return strings.Contains(as, bs)
	}

	// Slice element check.
	if slice, ok := a.([]interface{}); ok {
		target := fmt.Sprintf("%v", b)
		for _, elem := range slice {
			if fmt.Sprintf("%v", elem) == target {
				return true
			}
		}
	}

	return false
}

// valueGT returns true when a > b (numerically).
func valueGT(a, b interface{}) bool {
	af := toFloat64(a)
	bf := toFloat64(b)
	if af != nil && bf != nil {
		return *af > *bf
	}
	return false
}

// valueLT returns true when a < b (numerically).
func valueLT(a, b interface{}) bool {
	af := toFloat64(a)
	bf := toFloat64(b)
	if af != nil && bf != nil {
		return *af < *bf
	}
	return false
}

// valueMatches returns true when a matches the regex pattern b.
func valueMatches(a, b interface{}) bool {
	pattern, ok := b.(string)
	if !ok {
		pattern = fmt.Sprintf("%v", b)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(fmt.Sprintf("%v", a))
}

// ============================================================================
// Type-conversion helpers
// ============================================================================

// toFloat64 attempts to convert an interface value to *float64.
func toFloat64(v interface{}) *float64 {
	switch n := v.(type) {
	case float64:
		return &n
	case float32:
		f := float64(n)
		return &f
	case int:
		f := float64(n)
		return &f
	case int64:
		f := float64(n)
		return &f
	case json.Number:
		f, err := n.Float64()
		if err != nil {
			return nil
		}
		return &f
	}
	return nil
}

// toBool converts an interface to (bool, true) if the underlying value is
// boolean or a JSON-style bool.
func toBool(v interface{}) (bool, bool) {
	switch b := v.(type) {
	case bool:
		return b, true
	case string:
		switch strings.ToLower(b) {
		case "true":
			return true, true
		case "false":
			return false, true
		}
	}
	return false, false
}

// extractStringField is a convenience to pull a string from the top-level
// input map, returning "" if not present or not a string.
func extractStringField(input map[string]interface{}, key string) string {
	v, ok := input[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Sprintf("%v", v)
	}
	return s
}

// ============================================================================
// Default policies
// ============================================================================

// defaultPolicies returns the 10 built-in container security policies.
func defaultPolicies() []*models.OPAPolicy {
	return []*models.OPAPolicy{
		{
			Name:        "no-privileged-containers",
			Description: "Block containers running in privileged mode",
			Category:    models.OPACategoryAdmission,
			Severity:    "critical",
			IsEnabled:   true,
			IsEnforcing: true,
			RegoCode: mustJSON(RuleDefinition{Rules: []Rule{
				{Field: "privileged", Op: "neq", Value: true, Message: "Container runs in privileged mode"},
			}}),
		},
		{
			Name:        "no-root-user",
			Description: "Block containers running as root user (UID 0)",
			Category:    models.OPACategoryAdmission,
			Severity:    "high",
			IsEnabled:   true,
			IsEnforcing: true,
			RegoCode: mustJSON(RuleDefinition{Rules: []Rule{
				{Field: "config.user", Op: "neq", Value: "root", Message: "Container runs as root user"},
				{Field: "config.user", Op: "neq", Value: "0", Message: "Container runs as UID 0"},
			}}),
		},
		{
			Name:        "require-resource-limits",
			Description: "Require memory and CPU limits to be set",
			Category:    models.OPACategoryAdmission,
			Severity:    "medium",
			IsEnabled:   true,
			IsEnforcing: false,
			RegoCode: mustJSON(RuleDefinition{Rules: []Rule{
				{Field: "resources.memory_limit", Op: "exists", Value: nil, Message: "Memory limit is not set"},
				{Field: "resources.cpu_limit", Op: "exists", Value: nil, Message: "CPU limit is not set"},
				{Field: "resources.memory_limit", Op: "gt", Value: float64(0), Message: "Memory limit must be greater than zero"},
				{Field: "resources.cpu_limit", Op: "gt", Value: float64(0), Message: "CPU limit must be greater than zero"},
			}}),
		},
		{
			Name:        "no-host-network",
			Description: "Block containers using host network mode",
			Category:    models.OPACategoryNetwork,
			Severity:    "high",
			IsEnabled:   true,
			IsEnforcing: true,
			RegoCode: mustJSON(RuleDefinition{Rules: []Rule{
				{Field: "network_mode", Op: "neq", Value: "host", Message: "Container uses host network mode"},
			}}),
		},
		{
			Name:        "no-host-pid",
			Description: "Block containers sharing the host PID namespace",
			Category:    models.OPACategoryAdmission,
			Severity:    "high",
			IsEnabled:   true,
			IsEnforcing: true,
			RegoCode: mustJSON(RuleDefinition{Rules: []Rule{
				{Field: "pid_mode", Op: "neq", Value: "host", Message: "Container shares host PID namespace"},
			}}),
		},
		{
			Name:        "require-healthcheck",
			Description: "Require a health check to be configured",
			Category:    models.OPACategoryRuntime,
			Severity:    "low",
			IsEnabled:   true,
			IsEnforcing: false,
			RegoCode: mustJSON(RuleDefinition{Rules: []Rule{
				{Field: "healthcheck.test", Op: "exists", Value: nil, Message: "No health check configured"},
			}}),
		},
		{
			Name:        "no-dangerous-capabilities",
			Description: "Block dangerous Linux capabilities (SYS_ADMIN, NET_ADMIN, ALL, SYS_PTRACE, NET_RAW)",
			Category:    models.OPACategoryAdmission,
			Severity:    "critical",
			IsEnabled:   true,
			IsEnforcing: true,
			RegoCode: mustJSON(RuleDefinition{Rules: []Rule{
				{Field: "capabilities.add", Op: "not_contains", Value: "SYS_ADMIN", Message: "Dangerous capability SYS_ADMIN added"},
				{Field: "capabilities.add", Op: "not_contains", Value: "NET_ADMIN", Message: "Dangerous capability NET_ADMIN added"},
				{Field: "capabilities.add", Op: "not_contains", Value: "ALL", Message: "Dangerous capability ALL added"},
				{Field: "capabilities.add", Op: "not_contains", Value: "SYS_PTRACE", Message: "Dangerous capability SYS_PTRACE added"},
				{Field: "capabilities.add", Op: "not_contains", Value: "NET_RAW", Message: "Dangerous capability NET_RAW added"},
			}}),
		},
		{
			Name:        "require-read-only-rootfs",
			Description: "Require read-only root filesystem for containers",
			Category:    models.OPACategoryAdmission,
			Severity:    "medium",
			IsEnabled:   true,
			IsEnforcing: false,
			RegoCode: mustJSON(RuleDefinition{Rules: []Rule{
				{Field: "read_only_rootfs", Op: "eq", Value: true, Message: "Root filesystem is not read-only"},
			}}),
		},
		{
			Name:        "no-latest-tag",
			Description: "Block images using the :latest tag",
			Category:    models.OPACategoryImage,
			Severity:    "medium",
			IsEnabled:   true,
			IsEnforcing: false,
			RegoCode: mustJSON(RuleDefinition{Rules: []Rule{
				{Field: "image", Op: "not_contains", Value: ":latest", Message: "Image uses the :latest tag"},
				{Field: "image_tag", Op: "neq", Value: "latest", Message: "Image tag is 'latest'"},
			}}),
		},
		{
			Name:        "require-labels",
			Description: "Require minimum labels (app, version) on containers",
			Category:    models.OPACategoryGeneral,
			Severity:    "low",
			IsEnabled:   true,
			IsEnforcing: false,
			RegoCode: mustJSON(RuleDefinition{Rules: []Rule{
				{Field: "labels.app", Op: "exists", Value: nil, Message: "Required label 'app' is missing"},
				{Field: "labels.version", Op: "exists", Value: nil, Message: "Required label 'version' is missing"},
			}}),
		},
	}
}

// mustJSON marshals v to a JSON string and panics on failure. Used only
// during static default policy construction at program start.
func mustJSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("opa: failed to marshal default policy: %v", err))
	}
	return string(b)
}
