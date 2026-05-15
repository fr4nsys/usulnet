// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package config

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
)

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

type mockVariableStore struct {
	mu        sync.Mutex
	variables map[uuid.UUID]*models.ConfigVariable
	createErr error
	updateErr error
	deleteErr error
	getErr    error
	listErr   error
}

func newMockVariableStore() *mockVariableStore {
	return &mockVariableStore{variables: make(map[uuid.UUID]*models.ConfigVariable)}
}

func (m *mockVariableStore) Create(_ context.Context, v *models.ConfigVariable) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.createErr != nil {
		return m.createErr
	}
	cp := *v
	m.variables[v.ID] = &cp
	return nil
}

func (m *mockVariableStore) GetByID(_ context.Context, id uuid.UUID) (*models.ConfigVariable, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.getErr != nil {
		return nil, m.getErr
	}
	v, ok := m.variables[id]
	if !ok {
		return nil, fmt.Errorf("variable not found")
	}
	cp := *v
	return &cp, nil
}

func (m *mockVariableStore) GetByName(_ context.Context, name string, scope models.VariableScope, _ *string) (*models.ConfigVariable, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, v := range m.variables {
		if v.Name == name && v.Scope == scope {
			cp := *v
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("variable not found")
}

func (m *mockVariableStore) Update(_ context.Context, v *models.ConfigVariable) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.updateErr != nil {
		return m.updateErr
	}
	cp := *v
	cp.Version++
	m.variables[v.ID] = &cp
	return nil
}

func (m *mockVariableStore) Delete(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.variables, id)
	return nil
}

func (m *mockVariableStore) List(_ context.Context, _ models.VariableListOptions) ([]*models.ConfigVariable, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.listErr != nil {
		return nil, 0, m.listErr
	}
	result := make([]*models.ConfigVariable, 0, len(m.variables))
	for _, v := range m.variables {
		cp := *v
		result = append(result, &cp)
	}
	return result, len(result), nil
}

func (m *mockVariableStore) ListByScope(_ context.Context, scope models.VariableScope, _ *string) ([]*models.ConfigVariable, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []*models.ConfigVariable
	for _, v := range m.variables {
		if v.Scope == scope {
			cp := *v
			result = append(result, &cp)
		}
	}
	return result, nil
}

func (m *mockVariableStore) GetHistory(_ context.Context, _ uuid.UUID, _ int) ([]*models.VariableHistory, error) {
	return []*models.VariableHistory{}, nil
}

func (m *mockVariableStore) GetHistoryVersion(_ context.Context, _ uuid.UUID, version int) (*models.VariableHistory, error) {
	return &models.VariableHistory{Version: version, Value: "historical-value"}, nil
}

func (m *mockVariableStore) ResolveForContainer(_ context.Context, _ string, _ *string) ([]*models.ConfigVariable, error) {
	return nil, nil
}

type mockTemplateStore struct {
	mu        sync.Mutex
	templates map[uuid.UUID]*models.ConfigTemplate
	createErr error
	getErr    error
}

func newMockTemplateStore() *mockTemplateStore {
	return &mockTemplateStore{templates: make(map[uuid.UUID]*models.ConfigTemplate)}
}

func (m *mockTemplateStore) Create(_ context.Context, t *models.ConfigTemplate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.createErr != nil {
		return m.createErr
	}
	cp := *t
	m.templates[t.ID] = &cp
	return nil
}

func (m *mockTemplateStore) GetByID(_ context.Context, id uuid.UUID) (*models.ConfigTemplate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.getErr != nil {
		return nil, m.getErr
	}
	t, ok := m.templates[id]
	if !ok {
		return nil, fmt.Errorf("template not found")
	}
	cp := *t
	return &cp, nil
}

func (m *mockTemplateStore) GetByName(_ context.Context, name string) (*models.ConfigTemplate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.templates {
		if t.Name == name {
			cp := *t
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("template not found")
}

func (m *mockTemplateStore) Update(_ context.Context, t *models.ConfigTemplate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *t
	m.templates[t.ID] = &cp
	return nil
}

func (m *mockTemplateStore) Delete(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.templates, id)
	return nil
}

func (m *mockTemplateStore) Exists(_ context.Context, name string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.templates {
		if t.Name == name {
			return true, nil
		}
	}
	return false, nil
}

func (m *mockTemplateStore) CopyTemplate(_ context.Context, _ uuid.UUID, name string, userID *uuid.UUID) (*models.ConfigTemplate, error) {
	t := &models.ConfigTemplate{ID: uuid.New(), Name: name, CreatedBy: userID}
	return t, nil
}

func (m *mockTemplateStore) List(_ context.Context, _ *string, _, _ int) ([]*models.ConfigTemplate, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]*models.ConfigTemplate, 0, len(m.templates))
	for _, t := range m.templates {
		cp := *t
		result = append(result, &cp)
	}
	return result, len(result), nil
}

func (m *mockTemplateStore) ListAll(_ context.Context) ([]*models.ConfigTemplate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]*models.ConfigTemplate, 0, len(m.templates))
	for _, t := range m.templates {
		cp := *t
		result = append(result, &cp)
	}
	return result, nil
}

func (m *mockTemplateStore) SetDefault(_ context.Context, _ uuid.UUID) error {
	return nil
}

type mockAuditStore struct {
	entries   []*postgres.AuditLogEntry
	createErr error
}

func (m *mockAuditStore) Create(_ context.Context, entry *postgres.AuditLogEntry) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.entries = append(m.entries, entry)
	return nil
}

func (m *mockAuditStore) List(_ context.Context, _ postgres.AuditListOptions) ([]*models.ConfigAuditLog, int, error) {
	return nil, 0, nil
}

type mockSyncStore struct{}

func (m *mockSyncStore) List(_ context.Context, _ postgres.SyncListOptions) ([]*models.ConfigSync, int, error) {
	return nil, 0, nil
}

func (m *mockSyncStore) Create(_ context.Context, _ *models.ConfigSync) error {
	return nil
}

func (m *mockSyncStore) GetByContainer(_ context.Context, _ uuid.UUID, _ string) (*models.ConfigSync, error) {
	return nil, fmt.Errorf("not found")
}

func (m *mockSyncStore) UpdateStatus(_ context.Context, _ uuid.UUID, _ string, _ *string) error {
	return nil
}

func (m *mockSyncStore) ListOutdated(_ context.Context, _ *uuid.UUID) ([]*models.ConfigSync, error) {
	return nil, nil
}

func (m *mockSyncStore) GetSyncStats(_ context.Context, _ *uuid.UUID) (map[string]int, error) {
	return map[string]int{}, nil
}

func (m *mockSyncStore) DeleteByContainer(_ context.Context, _ uuid.UUID, _ string) error {
	return nil
}

type mockEncryptor struct {
	encryptErr error
	decryptErr error
}

func (e *mockEncryptor) EncryptString(plaintext string) (string, error) {
	if e.encryptErr != nil {
		return "", e.encryptErr
	}
	return "enc:" + plaintext, nil
}

func (e *mockEncryptor) DecryptString(ciphertext string) (string, error) {
	if e.decryptErr != nil {
		return "", e.decryptErr
	}
	return strings.TrimPrefix(ciphertext, "enc:"), nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestService() (*Service, *mockVariableStore, *mockTemplateStore, *mockAuditStore, *mockEncryptor) {
	vs := newMockVariableStore()
	ts := newMockTemplateStore()
	as := &mockAuditStore{}
	ss := &mockSyncStore{}
	enc := &mockEncryptor{}
	svc := NewService(vs, ts, as, ss, enc, logger.Nop())
	return svc, vs, ts, as, enc
}

func strPtr(s string) *string { return &s }

// ---------------------------------------------------------------------------
// Interface compliance
// ---------------------------------------------------------------------------

func TestMock_InterfaceCompliance(t *testing.T) {
	var _ VariableStore = (*mockVariableStore)(nil)
	var _ TemplateStore = (*mockTemplateStore)(nil)
	var _ AuditStore = (*mockAuditStore)(nil)
	var _ SyncStore = (*mockSyncStore)(nil)
	var _ Encryptor = (*mockEncryptor)(nil)
}

// ---------------------------------------------------------------------------
// Tests: Pure function — isValidVariableName
// ---------------------------------------------------------------------------

func TestIsValidVariableName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"simple uppercase", "MY_VAR", true},
		{"single letter", "A", true},
		{"with numbers", "VAR_123", true},
		{"all caps no underscore", "MYVAR", true},
		{"lowercase", "my_var", false},
		{"starts with number", "1VAR", false},
		{"starts with underscore", "_VAR", false},
		{"mixed case", "My_Var", false},
		{"empty", "", false},
		{"spaces", "MY VAR", false},
		{"hyphens", "MY-VAR", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidVariableName(tt.input)
			if got != tt.want {
				t.Errorf("isValidVariableName(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Tests: Pure function — maskIfSecret
// ---------------------------------------------------------------------------

func TestMaskIfSecret(t *testing.T) {
	t.Run("secret type returns masked", func(t *testing.T) {
		result := maskIfSecret("my-secret-value", models.VariableTypeSecret)
		if result == nil || *result != "********" {
			t.Errorf("expected masked value, got %v", result)
		}
	})

	t.Run("non-secret type returns original", func(t *testing.T) {
		result := maskIfSecret("plain-value", models.VariableTypePlain)
		if result == nil || *result != "plain-value" {
			t.Errorf("expected plain value, got %v", result)
		}
	})
}

// ---------------------------------------------------------------------------
// Tests: computeValue
// ---------------------------------------------------------------------------

func TestComputeValue(t *testing.T) {
	svc, _, _, _, _ := newTestService()

	t.Run("uuid", func(t *testing.T) {
		result, err := svc.computeValue("uuid")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := uuid.Parse(result); err != nil {
			t.Errorf("expected valid UUID, got %q", result)
		}
	})

	t.Run("UUID uppercase", func(t *testing.T) {
		result, err := svc.computeValue("UUID")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := uuid.Parse(result); err != nil {
			t.Errorf("expected valid UUID, got %q", result)
		}
	})

	t.Run("timestamp", func(t *testing.T) {
		result, err := svc.computeValue("timestamp")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == "" {
			t.Error("expected non-empty timestamp")
		}
	})

	t.Run("unix", func(t *testing.T) {
		result, err := svc.computeValue("unix")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == "" || result == "0" {
			t.Error("expected non-zero unix timestamp")
		}
	})

	t.Run("random:16", func(t *testing.T) {
		result, err := svc.computeValue("random:16")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result) != 16 {
			t.Errorf("expected 16-char string, got %d chars: %q", len(result), result)
		}
	})

	t.Run("passthrough unknown", func(t *testing.T) {
		result, err := svc.computeValue("some-expression")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != "some-expression" {
			t.Errorf("expected passthrough, got %q", result)
		}
	})
}

// ---------------------------------------------------------------------------
// Tests: CreateVariable
// ---------------------------------------------------------------------------

func TestCreateVariable_HappyPath(t *testing.T) {
	svc, _, _, _, _ := newTestService()
	ctx := context.Background()

	input := models.CreateVariableInput{
		Name:  "MY_VAR",
		Value: "hello",
		Type:  models.VariableTypePlain,
		Scope: models.VariableScopeGlobal,
	}

	v, err := svc.CreateVariable(ctx, input, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Name != "MY_VAR" {
		t.Errorf("name = %q, want %q", v.Name, "MY_VAR")
	}
	if v.Value != "hello" {
		t.Errorf("value = %q, want %q", v.Value, "hello")
	}
}

func TestCreateVariable_InvalidName(t *testing.T) {
	svc, _, _, _, _ := newTestService()
	ctx := context.Background()

	input := models.CreateVariableInput{
		Name:  "invalid-name",
		Value: "hello",
		Type:  models.VariableTypePlain,
		Scope: models.VariableScopeGlobal,
	}

	_, err := svc.CreateVariable(ctx, input, nil)
	if err == nil {
		t.Fatal("expected error for invalid name, got nil")
	}
}

func TestCreateVariable_Secret_Encrypts(t *testing.T) {
	svc, store, _, _, _ := newTestService()
	ctx := context.Background()

	input := models.CreateVariableInput{
		Name:  "SECRET_KEY",
		Value: "my-secret",
		Type:  models.VariableTypeSecret,
		Scope: models.VariableScopeGlobal,
	}

	v, err := svc.CreateVariable(ctx, input, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check that the stored value is encrypted
	stored := store.variables[v.ID]
	if !strings.HasPrefix(stored.Value, "enc:") {
		t.Errorf("stored value = %q, want enc: prefix", stored.Value)
	}
}

func TestCreateVariable_Secret_EncryptorError(t *testing.T) {
	svc, _, _, _, enc := newTestService()
	enc.encryptErr = fmt.Errorf("encryption failed")
	ctx := context.Background()

	input := models.CreateVariableInput{
		Name:  "SECRET_KEY",
		Value: "my-secret",
		Type:  models.VariableTypeSecret,
		Scope: models.VariableScopeGlobal,
	}

	_, err := svc.CreateVariable(ctx, input, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestCreateVariable_Computed(t *testing.T) {
	svc, _, _, _, _ := newTestService()
	ctx := context.Background()

	input := models.CreateVariableInput{
		Name:  "GENERATED_ID",
		Value: "uuid",
		Type:  models.VariableTypeComputed,
		Scope: models.VariableScopeGlobal,
	}

	v, err := svc.CreateVariable(ctx, input, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Value should be a UUID, not "uuid"
	if _, err := uuid.Parse(v.Value); err != nil {
		t.Errorf("expected UUID value, got %q", v.Value)
	}
}

func TestCreateVariable_TemplateScope_ValidatesExists(t *testing.T) {
	svc, _, ts, _, _ := newTestService()
	ctx := context.Background()

	tmplID := uuid.New()
	ts.templates[tmplID] = &models.ConfigTemplate{ID: tmplID, Name: "test-tmpl"}

	scopeID := "test-tmpl"
	input := models.CreateVariableInput{
		Name:    "TMPL_VAR",
		Value:   "value",
		Type:    models.VariableTypePlain,
		Scope:   models.VariableScopeTemplate,
		ScopeID: &scopeID,
	}

	v, err := svc.CreateVariable(ctx, input, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Name != "TMPL_VAR" {
		t.Errorf("name = %q, want %q", v.Name, "TMPL_VAR")
	}
}

func TestCreateVariable_TemplateScope_NotFound(t *testing.T) {
	svc, _, _, _, _ := newTestService()
	ctx := context.Background()

	missingScope := "nonexistent-template"
	input := models.CreateVariableInput{
		Name:    "TMPL_VAR",
		Value:   "value",
		Type:    models.VariableTypePlain,
		Scope:   models.VariableScopeTemplate,
		ScopeID: &missingScope,
	}

	_, err := svc.CreateVariable(ctx, input, nil)
	if err == nil {
		t.Fatal("expected error for missing template, got nil")
	}
}

func TestCreateVariable_StoreError(t *testing.T) {
	svc, store, _, _, _ := newTestService()
	store.createErr = fmt.Errorf("db error")

	input := models.CreateVariableInput{
		Name:  "MY_VAR",
		Value: "val",
		Type:  models.VariableTypePlain,
		Scope: models.VariableScopeGlobal,
	}

	_, err := svc.CreateVariable(context.Background(), input, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestCreateVariable_AuditLogCreated(t *testing.T) {
	svc, _, _, audit, _ := newTestService()
	ctx := context.Background()

	input := models.CreateVariableInput{
		Name:  "AUDIT_VAR",
		Value: "val",
		Type:  models.VariableTypePlain,
		Scope: models.VariableScopeGlobal,
	}

	_, err := svc.CreateVariable(ctx, input, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(audit.entries) != 1 {
		t.Errorf("expected 1 audit entry, got %d", len(audit.entries))
	}
	if audit.entries[0].Action != "create" {
		t.Errorf("audit action = %q, want %q", audit.entries[0].Action, "create")
	}
}

// ---------------------------------------------------------------------------
// Tests: GetVariable
// ---------------------------------------------------------------------------

func TestGetVariable_HappyPath(t *testing.T) {
	svc, store, _, _, _ := newTestService()
	id := uuid.New()
	store.variables[id] = &models.ConfigVariable{
		ID: id, Name: "GET_VAR", Value: "val", Type: models.VariableTypePlain,
	}

	v, err := svc.GetVariable(context.Background(), id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Value != "val" {
		t.Errorf("value = %q, want %q", v.Value, "val")
	}
}

func TestGetVariable_SecretIsMasked(t *testing.T) {
	svc, store, _, _, _ := newTestService()
	id := uuid.New()
	store.variables[id] = &models.ConfigVariable{
		ID: id, Name: "SECRET", Value: "enc:real-secret", Type: models.VariableTypeSecret,
	}

	v, err := svc.GetVariable(context.Background(), id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Value != "********" {
		t.Errorf("value = %q, want masked", v.Value)
	}
}

func TestGetVariable_NotFound(t *testing.T) {
	svc, _, _, _, _ := newTestService()

	_, err := svc.GetVariable(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// Tests: GetVariableDecrypted
// ---------------------------------------------------------------------------

func TestGetVariableDecrypted_Secret(t *testing.T) {
	svc, store, _, _, _ := newTestService()
	id := uuid.New()
	store.variables[id] = &models.ConfigVariable{
		ID: id, Name: "SECRET", Value: "enc:real-secret", Type: models.VariableTypeSecret,
	}

	v, err := svc.GetVariableDecrypted(context.Background(), id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Value != "real-secret" {
		t.Errorf("value = %q, want %q", v.Value, "real-secret")
	}
}

func TestGetVariableDecrypted_NonSecret(t *testing.T) {
	svc, store, _, _, _ := newTestService()
	id := uuid.New()
	store.variables[id] = &models.ConfigVariable{
		ID: id, Name: "PLAIN", Value: "plain-value", Type: models.VariableTypePlain,
	}

	v, err := svc.GetVariableDecrypted(context.Background(), id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Value != "plain-value" {
		t.Errorf("value = %q, want %q", v.Value, "plain-value")
	}
}

func TestGetVariableDecrypted_DecryptError(t *testing.T) {
	svc, store, _, _, enc := newTestService()
	enc.decryptErr = fmt.Errorf("decrypt failed")
	id := uuid.New()
	store.variables[id] = &models.ConfigVariable{
		ID: id, Name: "SECRET", Value: "enc:something", Type: models.VariableTypeSecret,
	}

	_, err := svc.GetVariableDecrypted(context.Background(), id)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// Tests: UpdateVariable
// ---------------------------------------------------------------------------

func TestUpdateVariable_HappyPath(t *testing.T) {
	svc, store, _, _, _ := newTestService()
	id := uuid.New()
	store.variables[id] = &models.ConfigVariable{
		ID: id, Name: "MY_VAR", Value: "old", Type: models.VariableTypePlain, Version: 1,
	}

	newVal := "new-value"
	v, err := svc.UpdateVariable(context.Background(), id, models.UpdateVariableInput{
		Value: &newVal,
	}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Value != "new-value" {
		t.Errorf("value = %q, want %q", v.Value, "new-value")
	}
}

func TestUpdateVariable_SecretEncrypts(t *testing.T) {
	svc, store, _, _, _ := newTestService()
	id := uuid.New()
	store.variables[id] = &models.ConfigVariable{
		ID: id, Name: "SECRET", Value: "enc:old", Type: models.VariableTypeSecret, Version: 1,
	}

	newVal := "new-secret"
	_, err := svc.UpdateVariable(context.Background(), id, models.UpdateVariableInput{
		Value: &newVal,
	}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stored := store.variables[id]
	if !strings.HasPrefix(stored.Value, "enc:") {
		t.Errorf("stored value = %q, want enc: prefix", stored.Value)
	}
}

func TestUpdateVariable_NotFound(t *testing.T) {
	svc, _, _, _, _ := newTestService()

	_, err := svc.UpdateVariable(context.Background(), uuid.New(), models.UpdateVariableInput{}, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// Tests: DeleteVariable
// ---------------------------------------------------------------------------

func TestDeleteVariable_HappyPath(t *testing.T) {
	svc, store, _, _, _ := newTestService()
	id := uuid.New()
	store.variables[id] = &models.ConfigVariable{
		ID: id, Name: "TO_DELETE", Value: "val", Type: models.VariableTypePlain,
	}

	err := svc.DeleteVariable(context.Background(), id, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, exists := store.variables[id]; exists {
		t.Error("expected variable to be deleted")
	}
}

func TestDeleteVariable_NotFound(t *testing.T) {
	svc, _, _, _, _ := newTestService()

	err := svc.DeleteVariable(context.Background(), uuid.New(), nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// Tests: ListVariables
// ---------------------------------------------------------------------------

func TestListVariables_MasksSecrets(t *testing.T) {
	svc, store, _, _, _ := newTestService()
	id1 := uuid.New()
	id2 := uuid.New()
	store.variables[id1] = &models.ConfigVariable{
		ID: id1, Name: "PLAIN", Value: "visible", Type: models.VariableTypePlain,
	}
	store.variables[id2] = &models.ConfigVariable{
		ID: id2, Name: "SECRET", Value: "enc:hidden", Type: models.VariableTypeSecret,
	}

	vars, total, err := svc.ListVariables(context.Background(), models.VariableListOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if total != 2 {
		t.Errorf("total = %d, want 2", total)
	}
	for _, v := range vars {
		if v.Type == models.VariableTypeSecret && v.Value != "********" {
			t.Errorf("secret %q should be masked, got %q", v.Name, v.Value)
		}
	}
}

// ---------------------------------------------------------------------------
// Tests: CreateTemplate
// ---------------------------------------------------------------------------

func TestCreateTemplate_HappyPath(t *testing.T) {
	svc, _, _, _, _ := newTestService()
	ctx := context.Background()

	input := models.CreateTemplateInput{
		Name:        "my-template",
		Description: strPtr("Test template"),
	}

	tmpl, err := svc.CreateTemplate(ctx, input, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tmpl.Name != "my-template" {
		t.Errorf("name = %q, want %q", tmpl.Name, "my-template")
	}
}

func TestCreateTemplate_CopyFrom(t *testing.T) {
	svc, _, ts, _, _ := newTestService()
	sourceID := uuid.New()
	ts.templates[sourceID] = &models.ConfigTemplate{
		ID: sourceID, Name: "source-template",
	}

	copyFrom := "source-template"
	input := models.CreateTemplateInput{
		Name:     "copied-template",
		CopyFrom: &copyFrom,
	}

	tmpl, err := svc.CreateTemplate(context.Background(), input, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tmpl.Name != "copied-template" {
		t.Errorf("name = %q, want %q", tmpl.Name, "copied-template")
	}
}

// ---------------------------------------------------------------------------
// Tests: UpdateTemplate
// ---------------------------------------------------------------------------

func TestUpdateTemplate_HappyPath(t *testing.T) {
	svc, _, ts, _, _ := newTestService()
	id := uuid.New()
	ts.templates[id] = &models.ConfigTemplate{ID: id, Name: "old-name"}

	newName := "new-name"
	tmpl, err := svc.UpdateTemplate(context.Background(), id, models.UpdateTemplateInput{
		Name: &newName,
	}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tmpl.Name != "new-name" {
		t.Errorf("name = %q, want %q", tmpl.Name, "new-name")
	}
}

// ---------------------------------------------------------------------------
// Tests: DeleteTemplate
// ---------------------------------------------------------------------------

func TestDeleteTemplate_HappyPath(t *testing.T) {
	svc, _, ts, _, _ := newTestService()
	id := uuid.New()
	ts.templates[id] = &models.ConfigTemplate{ID: id, Name: "to-delete"}

	err := svc.DeleteTemplate(context.Background(), id, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, exists := ts.templates[id]; exists {
		t.Error("expected template to be deleted")
	}
}

// ---------------------------------------------------------------------------
// Tests: GetVariableHistory
// ---------------------------------------------------------------------------

func TestGetVariableHistory_MasksSecrets(t *testing.T) {
	svc, store, _, _, _ := newTestService()
	id := uuid.New()
	store.variables[id] = &models.ConfigVariable{
		ID: id, Name: "SECRET", Value: "enc:secret", Type: models.VariableTypeSecret,
	}

	history, err := svc.GetVariableHistory(context.Background(), id, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// History entries for secrets should be masked.
	for _, h := range history {
		if h.Value != "********" {
			t.Errorf("history value = %q, want masked", h.Value)
		}
	}
}
