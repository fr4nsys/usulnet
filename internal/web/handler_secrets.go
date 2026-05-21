// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	secrettmpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/secrets"
)

// SecretsTempl renders the secret management page.
func (h *Handler) SecretsTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Secret Management", "secrets")

	var secrets []secrettmpl.SecretView
	stats := secrettmpl.SecretStats{}
	now := time.Now()

	if h.managedSecretRepo != nil {
		dbSecrets, err := h.managedSecretRepo.List(ctx)
		if err == nil {
			for _, s := range dbSecrets {
				sv := secrettmpl.SecretView{
					ID:           s.ID.String(),
					Name:         s.Name,
					Description:  s.Description,
					Type:         s.Type,
					Scope:        s.Scope,
					ScopeTarget:  s.ScopeTarget,
					MaskedValue:  maskSecret(s.EncryptedValue),
					IsRotatable:  s.RotationDays > 0,
					RotationDays: s.RotationDays,
					LinkedCount:  s.LinkedCount,
					CreatedAt:    s.CreatedAt.Format("Jan 02 15:04"),
					UpdatedAt:    s.UpdatedAt.Format("Jan 02 15:04"),
				}
				if s.CreatedBy != nil {
					sv.CreatedBy = s.CreatedBy.String()
				}
				if s.LastRotatedAt != nil {
					sv.LastRotatedAt = s.LastRotatedAt.Format("Jan 02 15:04")
				}
				if s.ExpiresAt != nil {
					sv.ExpiresAt = s.ExpiresAt.Format("Jan 02 2006")
					if now.After(*s.ExpiresAt) {
						sv.IsExpired = true
						stats.ExpiredCount++
					} else if s.ExpiresAt.Sub(now) < 7*24*time.Hour {
						sv.IsExpiringSoon = true
						stats.ExpiringSoon++
					}
				}
				secrets = append(secrets, sv)
				stats.TotalSecrets++
				if s.RotationDays > 0 {
					stats.RotatableCount++
				}
				if s.LinkedCount > 0 {
					stats.LinkedSecrets++
				}
			}
		}
	}

	data := secrettmpl.SecretsData{
		PageData: pageData,
		Secrets:  secrets,
		Stats:    stats,
	}

	h.renderTempl(w, r, secrettmpl.Secrets(data))
}

// SecretCreate creates a new managed secret.
// secretCreateForm captures the secret creation inputs. The
// `value_long` field mirrors the textarea variant the template
// renders for multi-line secrets; the handler accepts whichever one
// the form submitted so existing templates do not need a rewrite.
type secretCreateForm struct {
	Name          string `form:"name" validate:"required,min=1,max=200"`
	Description   string `form:"description"`
	Type          string `form:"type"`
	Scope         string `form:"scope"`
	ScopeTarget   string `form:"scope_target"`
	Value         string `form:"value"`
	ValueLong     string `form:"value_long"`
	RotationDays  int    `form:"rotation_days" validate:"gte=0"`
	ExpiresInDays int    `form:"expires_in_days" validate:"gte=0"`
}

func (h *Handler) SecretCreate(w http.ResponseWriter, r *http.Request) {
	var form secretCreateForm
	if msg := BindForm(r, &form); msg != "" {
		h.setFlash(w, r, "error", msg)
		http.Redirect(w, r, "/secrets", http.StatusSeeOther)
		return
	}

	// Secret value can come from either the short input or the
	// textarea fallback. validator cannot express this either-or
	// constraint so it stays as an explicit check after binding.
	value := form.Value
	if value == "" {
		value = form.ValueLong
	}
	if value == "" {
		h.setFlash(w, r, "error", "Secret value is required")
		http.Redirect(w, r, "/secrets", http.StatusSeeOther)
		return
	}

	if h.managedSecretRepo != nil {
		now := time.Now()
		s := &ManagedSecretRecord{
			ID:             uuid.New(),
			Name:           form.Name,
			Description:    form.Description,
			Type:           form.Type,
			Scope:          form.Scope,
			ScopeTarget:    form.ScopeTarget,
			EncryptedValue: value,
			RotationDays:   form.RotationDays,
			CreatedAt:      now,
			UpdatedAt:      now,
		}

		if form.ExpiresInDays > 0 {
			expires := now.Add(time.Duration(form.ExpiresInDays) * 24 * time.Hour)
			s.ExpiresAt = &expires
		}

		if err := h.managedSecretRepo.Create(r.Context(), s); err != nil {
			h.setFlash(w, r, "error", "Failed to create secret: "+err.Error())
			http.Redirect(w, r, "/secrets", http.StatusSeeOther)
			return
		}
	}

	h.setFlash(w, r, "success", "Secret '"+form.Name+"' created securely")
	http.Redirect(w, r, "/secrets", http.StatusSeeOther)
}

// SecretDelete deletes a managed secret.
func (h *Handler) SecretDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if h.managedSecretRepo != nil {
		uid, err := uuid.Parse(id)
		if err == nil {
			// Check linked count before delete for warning
			if s, getErr := h.managedSecretRepo.GetByID(r.Context(), uid); getErr == nil && s.LinkedCount > 0 {
				h.managedSecretRepo.Delete(r.Context(), uid)
				h.setFlash(w, r, "warning", "Secret deleted, but container(s) were using it")
			} else {
				h.managedSecretRepo.Delete(r.Context(), uid)
				h.setFlash(w, r, "success", "Secret deleted")
			}
		}
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/secrets")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/secrets", http.StatusSeeOther)
}

// SecretRotate generates a new value for a secret.
func (h *Handler) SecretRotate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if h.managedSecretRepo != nil {
		uid, err := uuid.Parse(id)
		if err != nil {
			h.setFlash(w, r, "error", "Invalid secret ID")
			http.Redirect(w, r, "/secrets", http.StatusSeeOther)
			return
		}

		s, err := h.managedSecretRepo.GetByID(r.Context(), uid)
		if err != nil {
			h.setFlash(w, r, "error", "Secret not found")
			http.Redirect(w, r, "/secrets", http.StatusSeeOther)
			return
		}

		newValue, err := generateRandomSecret(32)
		if err != nil {
			h.setFlash(w, r, "error", "Failed to generate new secret value")
			http.Redirect(w, r, "/secrets", http.StatusSeeOther)
			return
		}

		now := time.Now()
		s.EncryptedValue = newValue
		s.LastRotatedAt = &now
		s.UpdatedAt = now

		if s.RotationDays > 0 {
			expires := now.Add(time.Duration(s.RotationDays) * 24 * time.Hour)
			s.ExpiresAt = &expires
		}

		if err := h.managedSecretRepo.Update(r.Context(), s); err != nil {
			h.setFlash(w, r, "error", "Failed to update secret: "+err.Error())
			http.Redirect(w, r, "/secrets", http.StatusSeeOther)
			return
		}

		h.setFlash(w, r, "success", "Secret '"+s.Name+"' rotated successfully")
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/secrets")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/secrets", http.StatusSeeOther)
}

// maskSecret returns a masked version of a secret value.
func maskSecret(value string) string {
	if len(value) <= 4 {
		return "****"
	}
	return "****" + value[len(value)-4:]
}

// generateRandomSecret generates a cryptographically secure random hex string.
func generateRandomSecret(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
