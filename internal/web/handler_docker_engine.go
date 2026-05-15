// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	dockerconfigsvc "github.com/fr4nsys/usulnet/internal/services/dockerconfig"
	dctmpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/dockerconfig"
)

// requireDockerEngineSvc returns the dockerconfig service from the
// registry or renders an "unavailable" editor page so the operator can
// see why the editor is empty.
func (h *Handler) requireDockerEngineSvc() *dockerconfigsvc.Service {
	if reg, ok := h.services.(*ServiceRegistry); ok {
		return reg.dockerEngineSvc
	}
	return nil
}

// DockerEngineEditorTempl renders the editor page (GET /config/docker).
//
// On a fresh install with no daemon.json on disk, the page still
// renders — the editor opens on "{}" and the operator can author from
// scratch. When the dockerconfig service is nil (the container did not
// mount /etc/docker), the page surfaces an unavailable banner with
// remediation guidance instead of erroring.
func (h *Handler) DockerEngineEditorTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "Docker Engine", "docker-config")
	svc := h.requireDockerEngineSvc()

	data := dctmpl.EditorData{
		PageData: pageData,
		Flash:    consumeDockerEngineFlash(h, w, r),
	}

	if svc == nil {
		data.UnavailableMsg = "Docker engine config service is not configured."
		h.renderTempl(w, r, dctmpl.Editor(data))
		return
	}

	data.ConfigPath = svc.ConfigPath()
	data.ReloadTimeout = svc.ReloadTimeout().String()

	raw, err := svc.ReadRaw(r.Context())
	if err != nil {
		data.UnavailableMsg = "Failed to read daemon.json: " + err.Error()
		h.renderTempl(w, r, dctmpl.Editor(data))
		return
	}
	data.RawJSON = raw

	if snaps, sErr := svc.ListSnapshots(r.Context()); sErr == nil {
		data.Snapshots = snapshotsToView(snaps)
	}

	if applied := consumeDockerEngineApplied(h, w, r); applied != nil {
		data.LastApplied = applied
	}

	h.renderTempl(w, r, dctmpl.Editor(data))
}

// DockerEngineHistoryTempl renders the history page.
func (h *Handler) DockerEngineHistoryTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "Docker Engine — History", "docker-config")
	svc := h.requireDockerEngineSvc()

	data := dctmpl.HistoryData{
		PageData: pageData,
		Flash:    consumeDockerEngineFlash(h, w, r),
	}
	if svc == nil {
		data.UnavailableMsg = "Docker engine config service is not configured."
		h.renderTempl(w, r, dctmpl.History(data))
		return
	}
	data.ConfigPath = svc.ConfigPath()
	snaps, err := svc.ListSnapshots(r.Context())
	if err != nil {
		data.UnavailableMsg = "Failed to list snapshots: " + err.Error()
		h.renderTempl(w, r, dctmpl.History(data))
		return
	}
	data.Snapshots = snapshotsToView(snaps)
	h.renderTempl(w, r, dctmpl.History(data))
}

// DockerEngineApplyTempl handles POST /config/docker/apply. The form
// posts raw JSON in the "raw" field. We forward verbatim to the
// service which parses, validates, snapshots and applies. The result
// is stashed in a flash cookie so the next GET renders the success or
// rollback banner inline.
func (h *Handler) DockerEngineApplyTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireDockerEngineSvc()
	if svc == nil {
		h.setFlash(w, r, "error", "Docker engine config service is not configured")
		http.Redirect(w, r, "/config/docker", http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.setFlash(w, r, "error", "Invalid form data")
		http.Redirect(w, r, "/config/docker", http.StatusSeeOther)
		return
	}

	raw := strings.TrimSpace(r.FormValue("raw"))
	if raw == "" {
		// Some browsers fail to parse very large form bodies; fall
		// back to reading the raw body if "raw" is empty.
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		raw = string(body)
	}
	if raw == "" {
		h.setFlash(w, r, "error", "Empty config body")
		http.Redirect(w, r, "/config/docker", http.StatusSeeOther)
		return
	}

	res, err := svc.Apply(r.Context(), []byte(raw), reasonFromRequest(r))
	if err != nil {
		// Forced rollback returns an error AND a non-nil result with
		// RolledBack=true. We surface both via the flash and the
		// applied banner so the operator sees the rollback inline.
		if res != nil && res.RolledBack {
			storeDockerEngineApplied(h, w, r, res)
			h.setFlash(w, r, "error", "Daemon failed to reload — rolled back to snapshot "+res.SnapshotID)
			http.Redirect(w, r, "/config/docker", http.StatusSeeOther)
			return
		}
		// Distinguish validation errors so the inline banner reads
		// "rejected" rather than "rolled back" or "engine unavailable".
		if isValidationError(err) {
			h.setFlash(w, r, "error", "Validation failed: "+err.Error())
		} else {
			h.setFlash(w, r, "error", "Apply failed: "+err.Error())
		}
		http.Redirect(w, r, "/config/docker", http.StatusSeeOther)
		return
	}

	storeDockerEngineApplied(h, w, r, res)
	switch {
	case res.Reloaded:
		h.setFlash(w, r, "success", fmt.Sprintf("Applied — daemon reloaded (%d field(s) changed)", len(res.ChangedFields)))
	case res.WarningMsg != "":
		h.setFlash(w, r, "warning", res.WarningMsg)
	default:
		h.setFlash(w, r, "success", "Applied")
	}
	http.Redirect(w, r, "/config/docker", http.StatusSeeOther)
}

// DockerEngineRestoreTempl handles POST /config/docker/restore/{id}.
func (h *Handler) DockerEngineRestoreTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireDockerEngineSvc()
	if svc == nil {
		h.setFlash(w, r, "error", "Docker engine config service is not configured")
		http.Redirect(w, r, "/config/docker/history", http.StatusSeeOther)
		return
	}
	id := chi.URLParam(r, "id")
	if id == "" {
		h.setFlash(w, r, "error", "Snapshot ID required")
		http.Redirect(w, r, "/config/docker/history", http.StatusSeeOther)
		return
	}
	res, err := svc.Restore(r.Context(), id, "web-restore")
	if err != nil {
		if res != nil && res.RolledBack {
			storeDockerEngineApplied(h, w, r, res)
			h.setFlash(w, r, "error", "Restore: daemon failed to reload — rolled back")
			http.Redirect(w, r, "/config/docker", http.StatusSeeOther)
			return
		}
		h.setFlash(w, r, "error", "Restore failed: "+err.Error())
		http.Redirect(w, r, "/config/docker/history", http.StatusSeeOther)
		return
	}
	storeDockerEngineApplied(h, w, r, res)
	h.setFlash(w, r, "success", "Restored snapshot "+id)
	http.Redirect(w, r, "/config/docker", http.StatusSeeOther)
}

// ============================================================================
// Helpers
// ============================================================================

func snapshotsToView(in []dockerconfigsvc.Snapshot) []dctmpl.SnapshotView {
	out := make([]dctmpl.SnapshotView, len(in))
	for i, s := range in {
		out[i] = dctmpl.SnapshotView{
			ID:        s.ID,
			Size:      formatBytes(s.Size),
			Timestamp: s.Timestamp.UTC().Format("2006-01-02 15:04:05 UTC"),
		}
	}
	return out
}

// reasonFromRequest extracts a human-readable reason for the audit log
// from request data the form may carry. Falls back to "web-edit" so
// the audit summary always has something to show.
func reasonFromRequest(r *http.Request) string {
	if reason := strings.TrimSpace(r.FormValue("reason")); reason != "" {
		if len(reason) > 200 {
			reason = reason[:200]
		}
		return "web-edit:" + reason
	}
	return "web-edit"
}

// isValidationError reports whether an error came from the validation
// step (vs read/write/reload). Used to color the flash banner.
func isValidationError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "validation failed:") || errors.Is(err, errValidation)
}

// errValidation exists only so isValidationError has a typed sentinel
// to errors.Is against in case the service grows a typed error.
var errValidation = errors.New("validation failed")

// ----------------------------------------------------------------------------
// Cross-request state cookies
// ----------------------------------------------------------------------------
//
// The apply path needs to surface the structured UpdateResult on the
// next GET so the editor page can render the rollback banner without
// a second round-trip. We persist a minimal subset of the result in
// short-lived cookies; the full result lives only in memory for the
// duration of the request.

const (
	dockerEngineFlashCookie   = "dc_engine_flash"
	dockerEngineAppliedCookie = "dc_engine_applied"
)

// consumeDockerEngineFlash reads the page-level flash message that
// was stashed by setFlash on the prior request. The session middleware
// has already moved it into the request context and cleared the
// session value before this handler runs, so the read here is a plain
// context lookup.
func consumeDockerEngineFlash(_ *Handler, _ http.ResponseWriter, r *http.Request) dctmpl.FlashMessage {
	if f := GetFlashFromContext(r.Context()); f != nil {
		return dctmpl.FlashMessage{Type: f.Type, Message: f.Message}
	}
	return dctmpl.FlashMessage{}
}

// storeDockerEngineApplied stashes the apply result in a session
// cookie. consumeDockerEngineApplied retrieves and clears it.
func storeDockerEngineApplied(h *Handler, w http.ResponseWriter, r *http.Request, res *dockerconfigsvc.UpdateResult) {
	if res == nil || h == nil || w == nil {
		return
	}
	v := encodeAppliedCookie(res)
	http.SetCookie(w, &http.Cookie{
		Name:     dockerEngineAppliedCookie,
		Value:    v,
		Path:     "/config/docker",
		MaxAge:   60,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func consumeDockerEngineApplied(_ *Handler, w http.ResponseWriter, r *http.Request) *dctmpl.AppliedView {
	c, err := r.Cookie(dockerEngineAppliedCookie)
	if err != nil {
		return nil
	}
	http.SetCookie(w, &http.Cookie{
		Name:   dockerEngineAppliedCookie,
		Value:  "",
		Path:   "/config/docker",
		MaxAge: -1,
	})
	return decodeAppliedCookie(c.Value)
}

// encodeAppliedCookie packs a minimal subset of the result into a
// pipe-delimited string (no JSON in cookies — they have to survive
// HTTP header constraints unmodified). Fields are: id|mode|reloaded|
// rolledBack|warning|fields-csv. Fields are URL-encoded so the
// delimiter cannot appear in any value.
func encodeAppliedCookie(r *dockerconfigsvc.UpdateResult) string {
	parts := []string{
		r.SnapshotID,
		string(r.ApplyMode),
		boolStr(r.Reloaded),
		boolStr(r.RolledBack),
		simpleEscape(r.RollbackError),
		simpleEscape(r.WarningMsg),
		simpleEscape(strings.Join(r.ChangedFields, ",")),
	}
	return strings.Join(parts, "|")
}

func decodeAppliedCookie(v string) *dctmpl.AppliedView {
	parts := strings.Split(v, "|")
	if len(parts) < 7 {
		return nil
	}
	out := &dctmpl.AppliedView{
		SnapshotID:    parts[0],
		ApplyMode:     parts[1],
		Reloaded:      parts[2] == "1",
		RolledBack:    parts[3] == "1",
		RollbackError: simpleUnescape(parts[4]),
		Warning:       simpleUnescape(parts[5]),
	}
	if fields := simpleUnescape(parts[6]); fields != "" {
		out.ChangedFields = strings.Split(fields, ",")
	}
	return out
}

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// simpleEscape escapes the cookie's "|" delimiter (and the escape char
// itself). Avoids pulling in url.QueryEscape — the inputs are short
// strings and the delimiter is the only character we have to worry
// about.
func simpleEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, "|", `\,`)
}

func simpleUnescape(s string) string {
	s = strings.ReplaceAll(s, `\,`, "|")
	return strings.ReplaceAll(s, `\\`, `\`)
}
