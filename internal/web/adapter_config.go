// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	configsvc "github.com/fr4nsys/usulnet/internal/services/config"
)

type configAdapter struct {
	svc *configsvc.Service
}

func (a *configAdapter) ListVariables(ctx context.Context, scope, scopeID string) ([]ConfigVarView, error) {
	if a.svc == nil {
		return nil, nil
	}

	opts := models.VariableListOptions{
		Limit: 500,
	}
	if scope != "" {
		s := models.VariableScope(scope)
		opts.Scope = &s
	}
	if scopeID != "" {
		opts.ScopeID = &scopeID
	}

	vars, _, err := a.svc.ListVariables(ctx, opts)
	if err != nil {
		return nil, err
	}

	views := make([]ConfigVarView, 0, len(vars))
	for _, v := range vars {
		view := ConfigVarView{
			ID:        v.ID.String(),
			Name:      v.Name,
			Value:     v.Value,
			IsSecret:  v.IsSecret(),
			VarType:   string(v.Type),
			Scope:     string(v.Scope),
			UpdatedAt: v.UpdatedAt.Format("2006-01-02 15:04:05"),
		}
		if v.ScopeID != nil {
			view.ScopeID = *v.ScopeID
		}
		if v.IsSecret() {
			view.Value = "••••••••" // Mask secrets in list view
		}
		views = append(views, view)
	}
	return views, nil
}

func (a *configAdapter) GetVariable(ctx context.Context, id string) (*ConfigVarView, error) {
	if a.svc == nil {
		return nil, nil
	}

	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid variable ID: %w", err)
	}

	v, err := a.svc.GetVariable(ctx, uid)
	if err != nil {
		return nil, err
	}

	view := &ConfigVarView{
		ID:        v.ID.String(),
		Name:      v.Name,
		Value:     v.Value,
		IsSecret:  v.IsSecret(),
		VarType:   string(v.Type),
		Scope:     string(v.Scope),
		UpdatedAt: v.UpdatedAt.Format("2006-01-02 15:04:05"),
	}
	if v.ScopeID != nil {
		view.ScopeID = *v.ScopeID
	}
	if v.IsSecret() {
		view.Value = "••••••••"
	}
	return view, nil
}

func (a *configAdapter) CreateVariable(ctx context.Context, v *ConfigVarView) error {
	if a.svc == nil {
		return ErrServiceNotConfigured
	}

	input := models.CreateVariableInput{
		Name:  v.Name,
		Value: v.Value,
		Type:  models.VariableType(v.VarType),
		Scope: models.VariableScope(v.Scope),
	}
	if v.ScopeID != "" {
		input.ScopeID = &v.ScopeID
	}

	_, err := a.svc.CreateVariable(ctx, input, nil)
	return err
}

func (a *configAdapter) UpdateVariable(ctx context.Context, v *ConfigVarView) error {
	if a.svc == nil {
		return ErrServiceNotConfigured
	}

	uid, err := uuid.Parse(v.ID)
	if err != nil {
		return fmt.Errorf("invalid variable ID: %w", err)
	}

	input := models.UpdateVariableInput{}
	if v.Value != "" && v.Value != "••••••••" {
		input.Value = &v.Value
	}

	_, err = a.svc.UpdateVariable(ctx, uid, input, nil)
	return err
}

func (a *configAdapter) DeleteVariable(ctx context.Context, id string) error {
	if a.svc == nil {
		return ErrServiceNotConfigured
	}

	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid variable ID: %w", err)
	}

	return a.svc.DeleteVariable(ctx, uid, nil)
}

func (a *configAdapter) ListTemplates(ctx context.Context) ([]interface{}, error) {
	if a.svc == nil {
		return nil, nil
	}

	templates, _, err := a.svc.ListTemplates(ctx, nil, 100, 0)
	if err != nil {
		return nil, err
	}

	result := make([]interface{}, 0, len(templates))
	for _, t := range templates {
		desc := ""
		if t.Description != nil {
			desc = *t.Description
		}
		result = append(result, map[string]interface{}{
			"id":          t.ID.String(),
			"name":        t.Name,
			"description": desc,
			"var_count":   t.VariableCount,
			"created_at":  t.CreatedAt.Format("2006-01-02 15:04:05"),
		})
	}
	return result, nil
}

func (a *configAdapter) CreateTemplate(ctx context.Context, input models.CreateTemplateInput, userID *uuid.UUID) (*models.ConfigTemplate, error) {
	if a.svc == nil {
		return nil, fmt.Errorf("config service not available")
	}
	return a.svc.CreateTemplate(ctx, input, userID)
}

func (a *configAdapter) UpdateTemplate(ctx context.Context, id uuid.UUID, input models.UpdateTemplateInput, userID *uuid.UUID) (*models.ConfigTemplate, error) {
	if a.svc == nil {
		return nil, fmt.Errorf("config service not available")
	}
	return a.svc.UpdateTemplate(ctx, id, input, userID)
}

func (a *configAdapter) GetAuditLogs(ctx context.Context, limit int) ([]interface{}, error) {
	if a.svc == nil {
		return nil, nil
	}

	logs, _, err := a.svc.GetAuditLog(ctx, postgres.AuditListOptions{
		Limit: limit,
	})
	if err != nil {
		return nil, err
	}

	result := make([]interface{}, 0, len(logs))
	for _, l := range logs {
		entry := map[string]interface{}{
			"id":          l.ID,
			"action":      l.Action,
			"entity_type": l.EntityType,
			"entity_id":   l.EntityID,
			"entity_name": l.EntityName,
			"created_at":  l.CreatedAt.Format("2006-01-02 15:04:05"),
		}
		if l.Username != nil {
			entry["username"] = *l.Username
		}
		result = append(result, entry)
	}
	return result, nil
}
