// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"net"
	"net/http"
	"strconv"

	"github.com/fr4nsys/usulnet/internal/models"
	capturesvc "github.com/fr4nsys/usulnet/internal/services/capture"
	toolspages "github.com/fr4nsys/usulnet/internal/web/templates/pages/tools"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// CaptureService defines the interface for packet capture operations.
type CaptureService interface {
	Available() bool
	StartCapture(ctx context.Context, userID uuid.UUID, input models.CreateCaptureInput) (*models.PacketCapture, error)
	StopCapture(ctx context.Context, id uuid.UUID) error
	GetCapture(ctx context.Context, id uuid.UUID) (*models.PacketCapture, error)
	ListCaptures(ctx context.Context, userID uuid.UUID) ([]*models.PacketCapture, error)
	DeleteCapture(ctx context.Context, id uuid.UUID) error
	GetPcapPath(ctx context.Context, id uuid.UUID) (string, error)
	Cleanup()
}

// SetCaptureService sets the capture service.
func (h *Handler) SetCaptureService(svc CaptureService) {
	h.captureService = svc
}

// ============================================================================
// Packet Capture Handlers
// ============================================================================

// PacketCapture renders the packet capture page.
// GET /tools/capture
func (h *Handler) PacketCapture(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "Packet Capture", "capture")

	data := toolspages.PacketCaptureData{
		PageData:   pageData,
		Interfaces: getNetworkInterfaces(),
	}

	// Load captures from database if service is available
	if h.captureService != nil {
		user := h.getUserData(r)
		if user != nil && user.ID != "" {
			if userID, parseErr := uuid.Parse(user.ID); parseErr == nil {
				captures, listErr := h.captureService.ListCaptures(r.Context(), userID)
				if listErr == nil {
					for _, c := range captures {
						session := toCaptureSession(c)
						data.Captures = append(data.Captures, session)
					}
				}
			}
		}

		// If a specific capture is requested, set it as active
		captureID := r.URL.Query().Get("id")
		if captureID != "" {
			if id, err := uuid.Parse(captureID); err == nil {
				capture, err := h.captureService.GetCapture(r.Context(), id)
				if err == nil {
					session := toCaptureSession(capture)
					data.Active = &session
				}
			}
		}
	}

	h.renderTempl(w, r, toolspages.PacketCapture(data))
}

// PacketCaptureStart starts a new packet capture.
// POST /tools/capture/start
func (h *Handler) PacketCaptureStart(w http.ResponseWriter, r *http.Request) {
	if h.captureService == nil {
		h.setFlash(w, r, "error", "Packet capture service is not available")
		http.Redirect(w, r, "/tools/capture", http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.setFlash(w, r, "error", "Invalid form data")
		http.Redirect(w, r, "/tools/capture", http.StatusSeeOther)
		return
	}

	name := r.FormValue("name")
	iface := r.FormValue("interface")
	filter := r.FormValue("filter")
	maxPacketsStr := r.FormValue("max_packets")
	maxDurationStr := r.FormValue("max_duration")

	if name == "" || iface == "" {
		h.setFlash(w, r, "error", "Name and interface are required")
		http.Redirect(w, r, "/tools/capture", http.StatusSeeOther)
		return
	}

	maxPackets := 0
	if maxPacketsStr != "" {
		if p, err := strconv.Atoi(maxPacketsStr); err == nil {
			maxPackets = p
		}
	}

	maxDuration := 0
	if maxDurationStr != "" {
		if d, err := strconv.Atoi(maxDurationStr); err == nil {
			maxDuration = d
		}
	}

	user := h.getUserData(r)
	if user == nil || user.ID == "" {
		h.setFlash(w, r, "error", "Not authenticated")
		http.Redirect(w, r, "/tools/capture", http.StatusSeeOther)
		return
	}
	userID, parseErr := uuid.Parse(user.ID)
	if parseErr != nil {
		h.setFlash(w, r, "error", "Invalid user session")
		http.Redirect(w, r, "/tools/capture", http.StatusSeeOther)
		return
	}

	input := models.CreateCaptureInput{
		Name:        name,
		Interface:   iface,
		Filter:      filter,
		MaxPackets:  maxPackets,
		MaxDuration: maxDuration,
	}

	capture, err := h.captureService.StartCapture(r.Context(), userID, input)
	if err != nil {
		h.setFlash(w, r, "error", "Failed to start capture: "+err.Error())
		http.Redirect(w, r, "/tools/capture", http.StatusSeeOther)
		return
	}

	h.setFlash(w, r, "success", "Capture started: "+name)
	http.Redirect(w, r, "/tools/capture?id="+capture.ID.String(), http.StatusSeeOther)
}

// PacketCaptureStop stops a running capture.
// POST /tools/capture/{id}/stop
func (h *Handler) PacketCaptureStop(w http.ResponseWriter, r *http.Request) {
	captureID := chi.URLParam(r, "id")
	if captureID == "" {
		h.setFlash(w, r, "error", "Missing capture ID")
		http.Redirect(w, r, "/tools/capture", http.StatusSeeOther)
		return
	}

	if h.captureService == nil {
		h.setFlash(w, r, "error", "Packet capture service is not available")
		http.Redirect(w, r, "/tools/capture", http.StatusSeeOther)
		return
	}

	id, err := uuid.Parse(captureID)
	if err != nil {
		h.setFlash(w, r, "error", "Invalid capture ID")
		http.Redirect(w, r, "/tools/capture", http.StatusSeeOther)
		return
	}

	if err := h.captureService.StopCapture(r.Context(), id); err != nil {
		h.setFlash(w, r, "error", "Failed to stop capture: "+err.Error())
		http.Redirect(w, r, "/tools/capture?id="+captureID, http.StatusSeeOther)
		return
	}

	h.setFlash(w, r, "success", "Capture stopped")
	http.Redirect(w, r, "/tools/capture?id="+captureID, http.StatusSeeOther)
}

// PacketCaptureDownload downloads the PCAP file.
// GET /tools/capture/{id}/download
func (h *Handler) PacketCaptureDownload(w http.ResponseWriter, r *http.Request) {
	captureID := chi.URLParam(r, "id")
	if captureID == "" {
		h.setFlash(w, r, "error", "Missing capture ID")
		http.Redirect(w, r, "/tools/capture", http.StatusSeeOther)
		return
	}

	if h.captureService == nil {
		h.setFlash(w, r, "error", "Packet capture service is not available")
		http.Redirect(w, r, "/tools/capture", http.StatusSeeOther)
		return
	}

	id, err := uuid.Parse(captureID)
	if err != nil {
		h.setFlash(w, r, "error", "Invalid capture ID")
		http.Redirect(w, r, "/tools/capture", http.StatusSeeOther)
		return
	}

	pcapPath, err := h.captureService.GetPcapPath(r.Context(), id)
	if err != nil {
		h.setFlash(w, r, "error", "PCAP file not found")
		http.Redirect(w, r, "/tools/capture?id="+captureID, http.StatusSeeOther)
		return
	}

	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", "attachment; filename=\"capture-"+captureID+".pcap\"")
	http.ServeFile(w, r, pcapPath)
}

// PacketCaptureDelete deletes a capture.
// DELETE /tools/capture/{id}
func (h *Handler) PacketCaptureDelete(w http.ResponseWriter, r *http.Request) {
	captureID := chi.URLParam(r, "id")
	if captureID == "" {
		h.setFlash(w, r, "error", "Missing capture ID")
		http.Redirect(w, r, "/tools/capture", http.StatusSeeOther)
		return
	}

	if h.captureService == nil {
		h.setFlash(w, r, "error", "Packet capture service is not available")
		http.Redirect(w, r, "/tools/capture", http.StatusSeeOther)
		return
	}

	id, err := uuid.Parse(captureID)
	if err != nil {
		h.setFlash(w, r, "error", "Invalid capture ID")
		http.Redirect(w, r, "/tools/capture", http.StatusSeeOther)
		return
	}

	if err := h.captureService.DeleteCapture(r.Context(), id); err != nil {
		h.setFlash(w, r, "error", "Failed to delete capture: "+err.Error())
		http.Redirect(w, r, "/tools/capture", http.StatusSeeOther)
		return
	}

	h.setFlash(w, r, "success", "Capture deleted")
	http.Redirect(w, r, "/tools/capture", http.StatusSeeOther)
}

// PacketCaptureDetail shows capture details.
// GET /tools/capture/{id}
func (h *Handler) PacketCaptureDetail(w http.ResponseWriter, r *http.Request) {
	captureID := chi.URLParam(r, "id")
	if captureID == "" {
		http.Redirect(w, r, "/tools/capture", http.StatusSeeOther)
		return
	}

	// Redirect to main page with ID as query param
	http.Redirect(w, r, "/tools/capture?id="+captureID, http.StatusSeeOther)
}

// ============================================================================
// Helper Functions
// ============================================================================

// toCaptureSession converts a model to the template's CaptureSession type.
func toCaptureSession(c *models.PacketCapture) toolspages.CaptureSession {
	view := capturesvc.ToCaptureSession(c)
	return toolspages.CaptureSession{
		ID:          view.ID,
		Name:        view.Name,
		Interface:   view.Interface,
		Filter:      view.Filter,
		Status:      view.Status,
		PacketCount: view.PacketCount,
		Size:        view.Size,
		Duration:    view.Duration,
		StartedAt:   view.StartedAt,
		StoppedAt:   view.StoppedAt,
		PcapFile:    view.PcapFile,
	}
}

// getNetworkInterfaces returns available network interfaces from the system.
func getNetworkInterfaces() []toolspages.NetworkInterface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return []toolspages.NetworkInterface{}
	}

	var result []toolspages.NetworkInterface
	for _, iface := range ifaces {
		ni := toolspages.NetworkInterface{
			Name:        iface.Name,
			DisplayName: iface.Name,
			Status:      "down",
		}

		if iface.Flags&net.FlagUp != 0 {
			ni.Status = "up"
		}

		addrs, err := iface.Addrs()
		if err == nil && len(addrs) > 0 {
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
					ni.IP = ipnet.IP.String()
					break
				}
			}
		}

		result = append(result, ni)
	}

	return result
}
