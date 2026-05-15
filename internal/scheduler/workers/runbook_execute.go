// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package workers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// RunbookRepo defines the repository interface for the runbook worker.
type RunbookRepo interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.Runbook, error)
	GetExecution(ctx context.Context, id uuid.UUID) (*models.RunbookExecution, error)
	UpdateExecution(ctx context.Context, exec *models.RunbookExecution) error
}

// ContainerActionService defines the container operations needed by the runbook worker.
type ContainerActionService interface {
	Start(ctx context.Context, id string) error
	Stop(ctx context.Context, id string) error
	Restart(ctx context.Context, id string) error
	Get(ctx context.Context, id string) (*ContainerInfo, error)
}

// RunbookNotificationSender dispatches notifications from runbook steps.
type RunbookNotificationSender interface {
	SendRunbookNotification(ctx context.Context, runbookName, stepName, channel, message string) error
}

// RunbookExecuteWorker handles background execution of runbooks.
type RunbookExecuteWorker struct {
	BaseWorker
	runbookRepo      RunbookRepo
	containerService ContainerActionService
	notifySvc        RunbookNotificationSender
	logger           *logger.Logger
}

// NewRunbookExecuteWorker creates a new runbook execution worker.
func NewRunbookExecuteWorker(repo RunbookRepo, containerSvc ContainerActionService, notifySvc RunbookNotificationSender, log *logger.Logger) *RunbookExecuteWorker {
	if log == nil {
		log = logger.Nop()
	}
	return &RunbookExecuteWorker{
		BaseWorker:       NewBaseWorker(models.JobTypeRunbookExecute),
		runbookRepo:      repo,
		containerService: containerSvc,
		notifySvc:        notifySvc,
		logger:           log.Named("runbook-execute"),
	}
}

// RunbookExecuteResult holds the result of a runbook execution.
type RunbookExecuteResult struct {
	RunbookID   uuid.UUID     `json:"runbook_id"`
	ExecutionID uuid.UUID     `json:"execution_id"`
	Status      string        `json:"status"`
	StepsRun    int           `json:"steps_run"`
	StepsTotal  int           `json:"steps_total"`
	Duration    time.Duration `json:"duration"`
}

// Execute runs the runbook steps asynchronously.
func (w *RunbookExecuteWorker) Execute(ctx context.Context, job *models.Job) (interface{}, error) {
	log := w.logger.With("job_id", job.ID)

	var payload models.RunbookExecutePayload
	if err := job.GetPayload(&payload); err != nil {
		return nil, errors.Wrap(err, errors.CodeValidation, "failed to parse payload")
	}

	if payload.RunbookID == uuid.Nil || payload.ExecutionID == uuid.Nil {
		return nil, errors.New(errors.CodeValidation, "runbook_id and execution_id are required")
	}

	// Get runbook definition
	rb, err := w.runbookRepo.GetByID(ctx, payload.RunbookID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "runbook not found")
	}

	// Get execution record
	exec, err := w.runbookRepo.GetExecution(ctx, payload.ExecutionID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "execution not found")
	}

	// Parse steps
	var steps []models.RunbookStep
	if rb.Steps != nil {
		if err := json.Unmarshal(rb.Steps, &steps); err != nil {
			w.markFailed(ctx, exec, "invalid step configuration: "+err.Error())
			return nil, errors.Wrap(err, errors.CodeValidation, "failed to parse steps")
		}
	}

	log.Info("executing runbook",
		"runbook_id", rb.ID,
		"runbook_name", rb.Name,
		"steps", len(steps),
		"trigger", payload.Trigger,
	)

	startTime := time.Now()
	stepResults := make([]map[string]interface{}, 0, len(steps))
	execStatus := "completed"
	hasStepFailures := false

	for i, step := range steps {
		select {
		case <-ctx.Done():
			execStatus = "canceled"
			break
		default:
		}

		if execStatus == "canceled" {
			break
		}

		stepStart := time.Now()
		result := map[string]interface{}{
			"order":      step.Order,
			"name":       step.Name,
			"type":       step.Type,
			"status":     "completed",
			"started_at": stepStart.Format(time.RFC3339),
		}

		switch step.Type {
		case "command", "docker_exec":
			result = w.executeDockerStep(ctx, step, result)

		case "wait":
			result = w.executeWaitStep(ctx, step, result)

		case "notify":
			channel := step.Config["channel"]
			message := step.Config["message"]
			if message == "" {
				message = fmt.Sprintf("Runbook step: %s", step.Name)
			}
			if w.notifySvc != nil {
				if err := w.notifySvc.SendRunbookNotification(ctx, rb.Name, step.Name, channel, message); err != nil {
					log.Error("runbook notification dispatch failed", "error", err)
					// Don't fail the step for notification errors
				} else {
					log.Info("runbook notification dispatched",
						"step_name", step.Name,
						"channel", channel,
					)
					result["channel"] = channel
				}
			} else {
				log.Info("runbook notification step (no dispatcher configured)",
					"step_name", step.Name,
					"channel", channel,
				)
				result["note"] = "notification logged only (no dispatcher configured)"
			}

		case "condition":
			result = w.executeConditionStep(ctx, step, result)

		case "api_call":
			result = w.executeAPICallStep(ctx, step, result)

		case "approval":
			result["status"] = "pending_approval"
			result["note"] = "Approval step paused execution. Requires manual approval."
			result["finished_at"] = time.Now().Format(time.RFC3339)
			stepResults = append(stepResults, result)
			// Save partial results and stop processing -- execution is paused
			exec.Status = models.ExecStatusWaitingApproval
			if resultsJSON, err := json.Marshal(stepResults); err == nil {
				exec.StepResults = resultsJSON
			}
			if err := w.runbookRepo.UpdateExecution(ctx, exec); err != nil {
				log.Error("failed to update execution for approval", "error", err)
			}
			log.Info("runbook paused for approval",
				"runbook_name", rb.Name,
				"step_name", step.Name,
				"execution_id", exec.ID,
			)
			return &RunbookExecuteResult{
				RunbookID:   rb.ID,
				ExecutionID: exec.ID,
				Status:      models.ExecStatusWaitingApproval,
				StepsRun:    len(stepResults),
				StepsTotal:  len(steps),
				Duration:    time.Since(startTime),
			}, nil

		default:
			result["status"] = "skipped"
			result["note"] = "unsupported step type: " + step.Type
		}

		result["finished_at"] = time.Now().Format(time.RFC3339)
		stepResults = append(stepResults, result)

		// Track step failures
		if result["status"] == "failed" {
			hasStepFailures = true
			if step.OnFailure == "stop" {
				execStatus = "failed"
				break
			}
		}

		// Update progress
		_ = i // suppress unused
	}

	// Finalize execution
	if hasStepFailures && execStatus == "completed" {
		execStatus = "partial_failure"
	}
	now := time.Now()
	exec.FinishedAt = &now
	exec.Status = execStatus

	if resultsJSON, err := json.Marshal(stepResults); err == nil {
		exec.StepResults = resultsJSON
	}

	if err := w.runbookRepo.UpdateExecution(ctx, exec); err != nil {
		log.Error("failed to update execution", "error", err)
	}

	log.Info("runbook execution completed",
		"runbook_name", rb.Name,
		"status", execStatus,
		"steps_run", len(stepResults),
		"duration", time.Since(startTime),
	)

	return &RunbookExecuteResult{
		RunbookID:   rb.ID,
		ExecutionID: exec.ID,
		Status:      execStatus,
		StepsRun:    len(stepResults),
		StepsTotal:  len(steps),
		Duration:    time.Since(startTime),
	}, nil
}

func (w *RunbookExecuteWorker) markFailed(ctx context.Context, exec *models.RunbookExecution, errMsg string) {
	exec.Status = "failed"
	now := time.Now()
	exec.FinishedAt = &now
	errResult, _ := json.Marshal([]map[string]interface{}{
		{"status": "failed", "error": errMsg},
	})
	exec.StepResults = errResult
	w.runbookRepo.UpdateExecution(ctx, exec)
}

func (w *RunbookExecuteWorker) executeDockerStep(ctx context.Context, step models.RunbookStep, result map[string]interface{}) map[string]interface{} {
	if w.containerService == nil {
		result["status"] = "skipped"
		result["error"] = "container service not available"
		return result
	}

	var containerID, action string
	if step.Config != nil {
		containerID = step.Config["container_id"]
		action = step.Config["action"]
	}
	if containerID == "" {
		result["status"] = "skipped"
		result["error"] = "missing container_id in step config"
		return result
	}

	var actionErr error
	switch action {
	case "start":
		actionErr = w.containerService.Start(ctx, containerID)
	case "stop":
		actionErr = w.containerService.Stop(ctx, containerID)
	case "restart":
		actionErr = w.containerService.Restart(ctx, containerID)
	default:
		actionErr = w.containerService.Restart(ctx, containerID)
		result["note"] = "defaulted to restart action"
	}

	if actionErr != nil {
		result["status"] = "failed"
		result["error"] = actionErr.Error()
	} else {
		result["action"] = action
	}
	return result
}

func (w *RunbookExecuteWorker) executeWaitStep(ctx context.Context, step models.RunbookStep, result map[string]interface{}) map[string]interface{} {
	seconds := step.Timeout
	if seconds <= 0 {
		seconds = 5
	}
	if seconds > 60 {
		seconds = 60
	}

	select {
	case <-ctx.Done():
		result["status"] = "canceled"
	case <-time.After(time.Duration(seconds) * time.Second):
		result["waited_seconds"] = seconds
	}
	return result
}

func (w *RunbookExecuteWorker) executeConditionStep(ctx context.Context, step models.RunbookStep, result map[string]interface{}) map[string]interface{} {
	if step.Config == nil {
		result["status"] = "failed"
		result["error"] = "condition step has no config"
		return result
	}

	condType := step.Config["condition_type"]
	switch condType {
	case "container_status":
		if w.containerService == nil {
			result["status"] = "failed"
			result["error"] = "container service not available"
			return result
		}

		containerID := step.Config["container_id"]
		expectedStatus := step.Config["expected_status"]
		if containerID == "" || expectedStatus == "" {
			result["status"] = "failed"
			result["error"] = "container_id and expected_status are required"
			return result
		}

		container, err := w.containerService.Get(ctx, containerID)
		if err != nil {
			result["status"] = "failed"
			result["error"] = "failed to get container: " + err.Error()
			return result
		}

		actualStatus := strings.ToLower(container.State)
		expectedLower := strings.ToLower(expectedStatus)
		passed := actualStatus == expectedLower

		result["condition_type"] = "container_status"
		result["actual_status"] = actualStatus
		result["expected_status"] = expectedLower
		result["passed"] = passed

		if passed {
			result["status"] = "completed"
		} else {
			result["status"] = "failed"
			result["error"] = fmt.Sprintf("container %s is '%s', expected '%s'", containerID, actualStatus, expectedLower)
		}

	case "compare":
		leftVal := step.Config["left_value"]
		operator := step.Config["operator"]
		rightVal := step.Config["right_value"]

		var passed bool
		switch operator {
		case "eq":
			passed = leftVal == rightVal
		case "neq":
			passed = leftVal != rightVal
		case "contains":
			passed = strings.Contains(leftVal, rightVal)
		default:
			result["status"] = "failed"
			result["error"] = "unsupported operator: " + operator
			return result
		}

		result["passed"] = passed
		if passed {
			result["status"] = "completed"
		} else {
			result["status"] = "failed"
			result["error"] = fmt.Sprintf("condition failed: '%s' %s '%s'", leftVal, operator, rightVal)
		}

	case "http_health":
		// HTTP health check: make GET request, check status code
		url := step.Config["url"]
		expectedStatus := step.Config["expected_status"]
		if url == "" {
			result["status"] = "failed"
			result["error"] = "http_health condition requires 'url' config"
			return result
		}
		if expectedStatus == "" {
			expectedStatus = "200"
		}
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Get(url)
		if err != nil {
			result["status"] = "failed"
			result["error"] = fmt.Sprintf("HTTP health check failed: %v", err)
			return result
		}
		defer resp.Body.Close()
		if strconv.Itoa(resp.StatusCode) != expectedStatus {
			result["status"] = "failed"
			result["error"] = fmt.Sprintf("expected status %s, got %d", expectedStatus, resp.StatusCode)
			return result
		}
		result["status"] = "completed"
		result["note"] = fmt.Sprintf("HTTP health check passed: %s returned %d", url, resp.StatusCode)

	case "dns_resolve":
		// DNS resolution check
		hostname := step.Config["hostname"]
		if hostname == "" {
			result["status"] = "failed"
			result["error"] = "dns_resolve condition requires 'hostname' config"
			return result
		}
		addrs, err := net.LookupHost(hostname)
		if err != nil {
			result["status"] = "failed"
			result["error"] = fmt.Sprintf("DNS resolution failed for %s: %v", hostname, err)
			return result
		}
		expectedIP := step.Config["expected_ip"]
		if expectedIP != "" {
			found := false
			for _, a := range addrs {
				if a == expectedIP {
					found = true
					break
				}
			}
			if !found {
				result["status"] = "failed"
				result["error"] = fmt.Sprintf("DNS resolved %s to %v, expected %s", hostname, addrs, expectedIP)
				return result
			}
		}
		result["status"] = "completed"
		result["note"] = fmt.Sprintf("DNS resolved %s to %v", hostname, addrs)

	case "metric_threshold":
		// Metric threshold check via metrics service
		metricName := step.Config["metric"]
		operator := step.Config["operator"]
		thresholdStr := step.Config["threshold"]
		if metricName == "" || operator == "" || thresholdStr == "" {
			result["status"] = "failed"
			result["error"] = "metric_threshold requires 'metric', 'operator', 'threshold' config"
			return result
		}
		// For now, metric_threshold is a placeholder that evaluates simple numeric comparisons
		// from config values. Full metrics integration would require a MetricsProvider.
		threshold, err := strconv.ParseFloat(thresholdStr, 64)
		if err != nil {
			result["status"] = "failed"
			result["error"] = fmt.Sprintf("invalid threshold: %s", thresholdStr)
			return result
		}
		valueStr := step.Config["value"]
		if valueStr == "" {
			result["status"] = "failed"
			result["error"] = "metric_threshold: no 'value' provided (metrics provider not connected)"
			return result
		}
		value, err := strconv.ParseFloat(valueStr, 64)
		if err != nil {
			result["status"] = "failed"
			result["error"] = fmt.Sprintf("invalid metric value: %s", valueStr)
			return result
		}
		var passed bool
		switch operator {
		case "gt":
			passed = value > threshold
		case "gte":
			passed = value >= threshold
		case "lt":
			passed = value < threshold
		case "lte":
			passed = value <= threshold
		case "eq":
			passed = value == threshold
		default:
			result["status"] = "failed"
			result["error"] = fmt.Sprintf("unknown operator: %s", operator)
			return result
		}
		if !passed {
			result["status"] = "failed"
			result["error"] = fmt.Sprintf("metric %s: value %.2f did not satisfy %s %.2f", metricName, value, operator, threshold)
			return result
		}
		result["status"] = "completed"
		result["note"] = fmt.Sprintf("metric %s: %.2f %s %.2f passed", metricName, value, operator, threshold)

	default:
		result["status"] = "failed"
		result["error"] = "unsupported condition_type: " + condType
	}

	return result
}

func (w *RunbookExecuteWorker) executeAPICallStep(ctx context.Context, step models.RunbookStep, result map[string]interface{}) map[string]interface{} {
	if step.Config == nil {
		result["status"] = "failed"
		result["error"] = "api_call step has no config"
		return result
	}

	apiURL := step.Config["url"]
	if apiURL == "" {
		result["status"] = "failed"
		result["error"] = "url is required for api_call step"
		return result
	}

	method := strings.ToUpper(step.Config["method"])
	if method == "" {
		method = "GET"
	}

	var bodyReader io.Reader
	if body := step.Config["body"]; body != "" && (method == "POST" || method == "PUT" || method == "PATCH") {
		bodyReader = strings.NewReader(body)
	}

	timeout := time.Duration(step.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if timeout > 30*time.Second {
		timeout = 30 * time.Second
	}

	client := &http.Client{Timeout: timeout}

	req, err := http.NewRequestWithContext(ctx, method, apiURL, bodyReader)
	if err != nil {
		result["status"] = "failed"
		result["error"] = "failed to create request: " + err.Error()
		return result
	}

	contentType := step.Config["content_type"]
	if contentType == "" {
		contentType = "application/json"
	}
	req.Header.Set("Content-Type", contentType)

	if authHeader := step.Config["auth_header"]; authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	req.Header.Set("User-Agent", "usulnet-runbook/1.0")

	resp, err := client.Do(req)
	if err != nil {
		result["status"] = "failed"
		result["error"] = "request failed: " + err.Error()
		return result
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	result["url"] = apiURL
	result["method"] = method
	result["response_status"] = resp.StatusCode
	result["response_body"] = string(respBody)

	if expectedStatus := step.Config["expected_status"]; expectedStatus != "" {
		if fmt.Sprintf("%d", resp.StatusCode) != expectedStatus {
			result["status"] = "failed"
			result["error"] = fmt.Sprintf("expected status %s, got %d", expectedStatus, resp.StatusCode)
			return result
		}
	} else if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		result["status"] = "failed"
		result["error"] = fmt.Sprintf("request returned non-2xx status: %d", resp.StatusCode)
		return result
	}

	result["status"] = "completed"
	return result
}
