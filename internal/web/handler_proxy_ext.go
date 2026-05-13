// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"io"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	proxy "github.com/fr4nsys/usulnet/internal/web/templates/pages/proxy"
)

// ============================================================================
// Certificates Handlers
// ============================================================================

func (h *Handler) CertListTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "SSL Certificates", "proxy")

	var connected bool
	var certs []proxy.CertView

	if proxySvc := h.services.Proxy(); proxySvc != nil {
		connected = proxySvc.IsConnected(ctx)
		if connected {
			if certList, err := proxySvc.ListCertificates(ctx); err == nil {
				for _, c := range certList {
					certs = append(certs, certViewToTempl(c))
				}
			}
		}
	}

	data := proxy.CertListData{
		PageData:     pageData,
		Connected:    connected,
		Certificates: certs,
	}
	h.renderTempl(w, r, proxy.CertList(data))
}

func (h *Handler) CertNewLETempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "New Let's Encrypt Certificate", "proxy")
	data := proxy.CertNewLEData{PageData: pageData}
	h.renderTempl(w, r, proxy.CertNewLE(data))
}

func (h *Handler) CertNewCustomTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "Upload Custom Certificate", "proxy")
	data := proxy.CertNewCustomData{PageData: pageData}
	h.renderTempl(w, r, proxy.CertNewCustom(data))
}

func (h *Handler) CertCreateLE(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	proxySvc := h.services.Proxy()
	if proxySvc == nil {
		h.setFlash(w, r, "error", "Proxy service not configured")
		http.Redirect(w, r, "/proxy/certificates", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/proxy/certificates/new/letsencrypt", http.StatusSeeOther)
		return
	}

	domainsRaw := r.FormValue("domain_names")
	domains := splitAndTrim(domainsRaw)
	email := r.FormValue("email")
	agree := r.FormValue("agree") == "on"
	challengeType := r.FormValue("challenge_type")
	dnsChallenge := challengeType == "dns"
	dnsProvider := r.FormValue("dns_provider")
	dnsCredentials := r.FormValue("dns_credentials")
	propagation, _ := strconv.Atoi(r.FormValue("propagation_seconds"))

	if err := proxySvc.RequestLECertificate(ctx, domains, email, agree, dnsChallenge, dnsProvider, dnsCredentials, propagation); err != nil {
		slog.Error("Failed to request LE certificate", "error", err)
		pageData := h.prepareTemplPageData(r, "New Let's Encrypt Certificate", "proxy")
		data := proxy.CertNewLEData{PageData: pageData, Error: err.Error()}
		h.renderTempl(w, r, proxy.CertNewLE(data))
		return
	}
	h.setFlash(w, r, "success", "Let's Encrypt certificate requested")
	http.Redirect(w, r, "/proxy/certificates", http.StatusSeeOther)
}

func (h *Handler) CertCreateCustom(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	proxySvc := h.services.Proxy()
	if proxySvc == nil {
		h.setFlash(w, r, "error", "Proxy service not configured")
		http.Redirect(w, r, "/proxy/certificates", http.StatusSeeOther)
		return
	}
	if err := r.ParseMultipartForm(10 << 20); err != nil { // 10MB max
		http.Redirect(w, r, "/proxy/certificates/new/custom", http.StatusSeeOther)
		return
	}

	niceName := r.FormValue("nice_name")

	// Try file upload first, then text content
	certData := readFileOrText(r, "certificate", "certificate_text")
	keyData := readFileOrText(r, "certificate_key", "certificate_key_text")
	intermediateData := readFileOrText(r, "intermediate_certificate", "intermediate_certificate_text")

	if len(certData) == 0 || len(keyData) == 0 {
		pageData := h.prepareTemplPageData(r, "Upload Custom Certificate", "proxy")
		data := proxy.CertNewCustomData{PageData: pageData, Error: "Certificate and private key are required"}
		h.renderTempl(w, r, proxy.CertNewCustom(data))
		return
	}

	if err := proxySvc.UploadCustomCertificate(ctx, niceName, certData, keyData, intermediateData); err != nil {
		slog.Error("Failed to upload custom certificate", "error", err)
		pageData := h.prepareTemplPageData(r, "Upload Custom Certificate", "proxy")
		data := proxy.CertNewCustomData{PageData: pageData, Error: err.Error()}
		h.renderTempl(w, r, proxy.CertNewCustom(data))
		return
	}
	h.setFlash(w, r, "success", "Custom certificate uploaded")
	http.Redirect(w, r, "/proxy/certificates", http.StatusSeeOther)
}

func (h *Handler) CertDetailTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, _ := strconv.Atoi(chi.URLParam(r, "id"))
	pageData := h.prepareTemplPageData(r, "Certificate Detail", "proxy")

	proxySvc := h.services.Proxy()
	if proxySvc == nil {
		h.setFlash(w, r, "error", "Proxy service not configured")
		http.Redirect(w, r, "/proxy/certificates", http.StatusSeeOther)
		return
	}

	cv, err := proxySvc.GetCertificate(ctx, id)
	if err != nil {
		h.setFlash(w, r, "error", "Certificate not found")
		http.Redirect(w, r, "/proxy/certificates", http.StatusSeeOther)
		return
	}

	data := proxy.CertDetailData{
		PageData: pageData,
		Cert:     certViewToTempl(*cv),
	}
	h.renderTempl(w, r, proxy.CertDetail(data))
}

func (h *Handler) CertRenew(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	proxySvc := h.services.Proxy()
	if proxySvc == nil {
		w.Header().Set("HX-Trigger", `{"showToast":{"message":"Proxy service not configured","type":"error"}}`)
		w.WriteHeader(http.StatusOK)
		return
	}
	id, _ := strconv.Atoi(chi.URLParam(r, "id"))
	if err := proxySvc.RenewCertificate(ctx, id); err != nil {
		slog.Error("Failed to renew certificate", "error", err)
		w.Header().Set("HX-Trigger", `{"showToast":{"message":"Failed to renew certificate: `+escapeJSON(err.Error())+`","type":"error"}}`)
		w.WriteHeader(http.StatusOK)
		return
	}
	w.Header().Set("HX-Trigger", `{"showToast":{"message":"Certificate renewal started","type":"success"}}`)
	w.Header().Set("HX-Redirect", "/proxy/certificates")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) CertDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	proxySvc := h.services.Proxy()
	if proxySvc == nil {
		w.Header().Set("HX-Trigger", `{"showToast":{"message":"Proxy service not configured","type":"error"}}`)
		w.WriteHeader(http.StatusOK)
		return
	}
	id, _ := strconv.Atoi(chi.URLParam(r, "id"))
	if err := proxySvc.DeleteCertificate(ctx, id); err != nil {
		slog.Error("Failed to delete certificate", "error", err)
		w.Header().Set("HX-Trigger", `{"showToast":{"message":"Failed to delete certificate: `+escapeJSON(err.Error())+`","type":"error"}}`)
		w.WriteHeader(http.StatusOK)
		return
	}
	w.Header().Set("HX-Trigger", `{"showToast":{"message":"Certificate deleted","type":"success"}}`)
	w.Header().Set("HX-Redirect", "/proxy/certificates")
	w.WriteHeader(http.StatusNoContent)
}

// ============================================================================
// Redirection Hosts Handlers
// ============================================================================

func (h *Handler) RedirListTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Redirections", "proxy")

	var connected bool
	var redirections []proxy.RedirView

	if proxySvc := h.services.Proxy(); proxySvc != nil {
		connected = proxySvc.IsConnected(ctx)
		if connected {
			if list, err := proxySvc.ListRedirections(ctx); err == nil {
				for _, rv := range list {
					redirections = append(redirections, proxy.RedirView{
						ID:              rv.ID,
						DomainNames:     rv.DomainNames,
						ForwardScheme:   rv.ForwardScheme,
						ForwardDomain:   rv.ForwardDomain,
						ForwardHTTPCode: rv.ForwardHTTPCode,
						PreservePath:    rv.PreservePath,
						SSLForced:       rv.SSLForced,
						CertificateID:   rv.CertificateID,
						Enabled:         rv.Enabled,
					})
				}
			}
		}
	}

	data := proxy.RedirListData{
		PageData:     pageData,
		Connected:    connected,
		Redirections: redirections,
	}
	h.renderTempl(w, r, proxy.RedirList(data))
}

func (h *Handler) RedirNewTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "New Redirection", "proxy")

	var certs []proxy.CertView
	if proxySvc := h.services.Proxy(); proxySvc != nil {
		if certList, err := proxySvc.ListCertificates(ctx); err == nil {
			for _, c := range certList {
				certs = append(certs, certViewToTempl(c))
			}
		}
	}

	data := proxy.RedirFormData{
		PageData:     pageData,
		IsEdit:       false,
		Certificates: certs,
	}
	h.renderTempl(w, r, proxy.RedirForm(data))
}

func (h *Handler) RedirCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	proxySvc := h.services.Proxy()
	if proxySvc == nil {
		h.setFlash(w, r, "error", "Proxy service not configured")
		http.Redirect(w, r, "/proxy/redirections", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/proxy/redirections/new", http.StatusSeeOther)
		return
	}

	httpCode, _ := strconv.Atoi(r.FormValue("forward_http_code"))
	certID, _ := strconv.Atoi(r.FormValue("certificate_id"))

	rv := &RedirectionHostView{
		DomainNames:     splitAndTrim(r.FormValue("domain_names")),
		ForwardScheme:   r.FormValue("forward_scheme"),
		ForwardDomain:   r.FormValue("forward_domain"),
		ForwardHTTPCode: httpCode,
		PreservePath:    r.FormValue("preserve_path") == "on",
		SSLForced:       r.FormValue("ssl_forced") == "on",
		CertificateID:   certID,
	}

	if err := proxySvc.CreateRedirection(ctx, rv); err != nil {
		slog.Error("Failed to create redirection", "error", err)
		h.setFlash(w, r, "error", "Failed to create redirection: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Redirection created")
	}
	http.Redirect(w, r, "/proxy/redirections", http.StatusSeeOther)
}

func (h *Handler) RedirEditTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, _ := strconv.Atoi(chi.URLParam(r, "id"))
	pageData := h.prepareTemplPageData(r, "Edit Redirection", "proxy")

	proxySvc := h.services.Proxy()
	if proxySvc == nil {
		h.setFlash(w, r, "error", "Proxy service not configured")
		http.Redirect(w, r, "/proxy/redirections", http.StatusSeeOther)
		return
	}

	rv, err := proxySvc.GetRedirection(ctx, id)
	if err != nil {
		h.setFlash(w, r, "error", "Redirection not found")
		http.Redirect(w, r, "/proxy/redirections", http.StatusSeeOther)
		return
	}

	var certs []proxy.CertView
	if certList, err := proxySvc.ListCertificates(ctx); err == nil {
		for _, c := range certList {
			certs = append(certs, certViewToTempl(c))
		}
	}

	templView := &proxy.RedirView{
		ID:              rv.ID,
		DomainNames:     rv.DomainNames,
		ForwardScheme:   rv.ForwardScheme,
		ForwardDomain:   rv.ForwardDomain,
		ForwardHTTPCode: rv.ForwardHTTPCode,
		PreservePath:    rv.PreservePath,
		SSLForced:       rv.SSLForced,
		CertificateID:   rv.CertificateID,
		Enabled:         rv.Enabled,
	}

	data := proxy.RedirFormData{
		PageData:     pageData,
		IsEdit:       true,
		Redir:        templView,
		Certificates: certs,
	}
	h.renderTempl(w, r, proxy.RedirForm(data))
}

func (h *Handler) RedirUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	proxySvc := h.services.Proxy()
	if proxySvc == nil {
		h.setFlash(w, r, "error", "Proxy service not configured")
		http.Redirect(w, r, "/proxy/redirections", http.StatusSeeOther)
		return
	}
	id, _ := strconv.Atoi(chi.URLParam(r, "id"))
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/proxy/redirections", http.StatusSeeOther)
		return
	}

	httpCode, _ := strconv.Atoi(r.FormValue("forward_http_code"))
	certID, _ := strconv.Atoi(r.FormValue("certificate_id"))

	rv := &RedirectionHostView{
		ID:              id,
		DomainNames:     splitAndTrim(r.FormValue("domain_names")),
		ForwardScheme:   r.FormValue("forward_scheme"),
		ForwardDomain:   r.FormValue("forward_domain"),
		ForwardHTTPCode: httpCode,
		PreservePath:    r.FormValue("preserve_path") == "on",
		SSLForced:       r.FormValue("ssl_forced") == "on",
		CertificateID:   certID,
		Enabled:         r.FormValue("enabled") == "on",
	}

	if err := proxySvc.UpdateRedirection(ctx, rv); err != nil {
		slog.Error("Failed to update redirection", "error", err)
		h.setFlash(w, r, "error", "Failed to update redirection: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Redirection updated")
	}
	http.Redirect(w, r, "/proxy/redirections", http.StatusSeeOther)
}

func (h *Handler) RedirDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	proxySvc := h.services.Proxy()
	if proxySvc == nil {
		w.Header().Set("HX-Trigger", `{"showToast":{"message":"Proxy service not configured","type":"error"}}`)
		w.WriteHeader(http.StatusOK)
		return
	}
	id, _ := strconv.Atoi(chi.URLParam(r, "id"))
	if err := proxySvc.DeleteRedirection(ctx, id); err != nil {
		slog.Error("Failed to delete redirection", "error", err)
		w.Header().Set("HX-Trigger", `{"showToast":{"message":"Failed to delete redirection: `+escapeJSON(err.Error())+`","type":"error"}}`)
		w.WriteHeader(http.StatusOK)
		return
	}
	w.Header().Set("HX-Trigger", `{"showToast":{"message":"Redirection deleted","type":"success"}}`)
	w.Header().Set("HX-Redirect", "/proxy/redirections")
	w.WriteHeader(http.StatusNoContent)
}

// ============================================================================
// Streams Handlers
// ============================================================================

func (h *Handler) StreamListTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Streams", "proxy")

	var connected bool
	var streams []proxy.StreamView

	if proxySvc := h.services.Proxy(); proxySvc != nil {
		connected = proxySvc.IsConnected(ctx)
		if connected {
			if list, err := proxySvc.ListStreams(ctx); err == nil {
				for _, s := range list {
					streams = append(streams, proxy.StreamView{
						ID:             s.ID,
						IncomingPort:   s.IncomingPort,
						ForwardingHost: s.ForwardingHost,
						ForwardingPort: s.ForwardingPort,
						TCPForwarding:  s.TCPForwarding,
						UDPForwarding:  s.UDPForwarding,
						Enabled:        s.Enabled,
					})
				}
			}
		}
	}

	data := proxy.StreamListData{
		PageData:  pageData,
		Connected: connected,
		Streams:   streams,
	}
	h.renderTempl(w, r, proxy.StreamList(data))
}

func (h *Handler) StreamNewTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "New Stream", "proxy")
	data := proxy.StreamFormData{PageData: pageData}
	h.renderTempl(w, r, proxy.StreamForm(data))
}

func (h *Handler) StreamCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	proxySvc := h.services.Proxy()
	if proxySvc == nil {
		h.setFlash(w, r, "error", "Proxy service not configured")
		http.Redirect(w, r, "/proxy/streams", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/proxy/streams/new", http.StatusSeeOther)
		return
	}

	inPort, _ := strconv.Atoi(r.FormValue("incoming_port"))
	fwdPort, _ := strconv.Atoi(r.FormValue("forwarding_port"))

	sv := &StreamView{
		IncomingPort:   inPort,
		ForwardingHost: r.FormValue("forwarding_host"),
		ForwardingPort: fwdPort,
		TCPForwarding:  r.FormValue("tcp_forwarding") == "on",
		UDPForwarding:  r.FormValue("udp_forwarding") == "on",
	}

	if err := proxySvc.CreateStream(ctx, sv); err != nil {
		slog.Error("Failed to create stream", "error", err)
		h.setFlash(w, r, "error", "Failed to create stream: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Stream created")
	}
	http.Redirect(w, r, "/proxy/streams", http.StatusSeeOther)
}

func (h *Handler) StreamEditTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, _ := strconv.Atoi(chi.URLParam(r, "id"))
	pageData := h.prepareTemplPageData(r, "Edit Stream", "proxy")

	proxySvc := h.services.Proxy()
	if proxySvc == nil {
		h.setFlash(w, r, "error", "Proxy service not configured")
		http.Redirect(w, r, "/proxy/streams", http.StatusSeeOther)
		return
	}

	sv, err := proxySvc.GetStream(ctx, id)
	if err != nil {
		h.setFlash(w, r, "error", "Stream not found")
		http.Redirect(w, r, "/proxy/streams", http.StatusSeeOther)
		return
	}

	templView := &proxy.StreamView{
		ID:             sv.ID,
		IncomingPort:   sv.IncomingPort,
		ForwardingHost: sv.ForwardingHost,
		ForwardingPort: sv.ForwardingPort,
		TCPForwarding:  sv.TCPForwarding,
		UDPForwarding:  sv.UDPForwarding,
		Enabled:        sv.Enabled,
	}

	data := proxy.StreamFormData{
		PageData: pageData,
		IsEdit:   true,
		Stream:   templView,
	}
	h.renderTempl(w, r, proxy.StreamForm(data))
}

func (h *Handler) StreamUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	proxySvc := h.services.Proxy()
	if proxySvc == nil {
		h.setFlash(w, r, "error", "Proxy service not configured")
		http.Redirect(w, r, "/proxy/streams", http.StatusSeeOther)
		return
	}
	id, _ := strconv.Atoi(chi.URLParam(r, "id"))
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/proxy/streams", http.StatusSeeOther)
		return
	}

	inPort, _ := strconv.Atoi(r.FormValue("incoming_port"))
	fwdPort, _ := strconv.Atoi(r.FormValue("forwarding_port"))

	sv := &StreamView{
		ID:             id,
		IncomingPort:   inPort,
		ForwardingHost: r.FormValue("forwarding_host"),
		ForwardingPort: fwdPort,
		TCPForwarding:  r.FormValue("tcp_forwarding") == "on",
		UDPForwarding:  r.FormValue("udp_forwarding") == "on",
		Enabled:        r.FormValue("enabled") == "on",
	}

	if err := proxySvc.UpdateStream(ctx, sv); err != nil {
		slog.Error("Failed to update stream", "error", err)
		h.setFlash(w, r, "error", "Failed to update stream: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Stream updated")
	}
	http.Redirect(w, r, "/proxy/streams", http.StatusSeeOther)
}

func (h *Handler) StreamDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	proxySvc := h.services.Proxy()
	if proxySvc == nil {
		w.Header().Set("HX-Trigger", `{"showToast":{"message":"Proxy service not configured","type":"error"}}`)
		w.WriteHeader(http.StatusOK)
		return
	}
	id, _ := strconv.Atoi(chi.URLParam(r, "id"))
	if err := proxySvc.DeleteStream(ctx, id); err != nil {
		slog.Error("Failed to delete stream", "error", err)
		w.Header().Set("HX-Trigger", `{"showToast":{"message":"Failed to delete stream: `+escapeJSON(err.Error())+`","type":"error"}}`)
		w.WriteHeader(http.StatusOK)
		return
	}
	w.Header().Set("HX-Trigger", `{"showToast":{"message":"Stream deleted","type":"success"}}`)
	w.Header().Set("HX-Redirect", "/proxy/streams")
	w.WriteHeader(http.StatusNoContent)
}

// ============================================================================
// Dead Hosts Handlers
// ============================================================================

func (h *Handler) DeadListTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "404 Hosts", "proxy")

	var connected bool
	var deadHosts []proxy.DeadHostView

	if proxySvc := h.services.Proxy(); proxySvc != nil {
		connected = proxySvc.IsConnected(ctx)
		if connected {
			if list, err := proxySvc.ListDeadHosts(ctx); err == nil {
				for _, d := range list {
					deadHosts = append(deadHosts, proxy.DeadHostView{
						ID:          d.ID,
						DomainNames: d.DomainNames,
						SSLForced:   d.SSLForced,
						CertID:      d.CertID,
						Enabled:     d.Enabled,
					})
				}
			}
		}
	}

	data := proxy.DeadListData{
		PageData:  pageData,
		Connected: connected,
		DeadHosts: deadHosts,
	}
	h.renderTempl(w, r, proxy.DeadList(data))
}

func (h *Handler) DeadNewTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "New 404 Host", "proxy")

	var certs []proxy.CertView
	if proxySvc := h.services.Proxy(); proxySvc != nil {
		if certList, err := proxySvc.ListCertificates(ctx); err == nil {
			for _, c := range certList {
				certs = append(certs, certViewToTempl(c))
			}
		}
	}

	data := proxy.DeadFormData{
		PageData:     pageData,
		Certificates: certs,
	}
	h.renderTempl(w, r, proxy.DeadForm(data))
}

func (h *Handler) DeadCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	proxySvc := h.services.Proxy()
	if proxySvc == nil {
		h.setFlash(w, r, "error", "Proxy service not configured")
		http.Redirect(w, r, "/proxy/dead-hosts", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/proxy/dead-hosts/new", http.StatusSeeOther)
		return
	}

	certID, _ := strconv.Atoi(r.FormValue("certificate_id"))

	dv := &DeadHostView{
		DomainNames: splitAndTrim(r.FormValue("domain_names")),
		SSLForced:   r.FormValue("ssl_forced") == "on",
		CertID:      certID,
		Enabled:     true,
	}

	if err := proxySvc.CreateDeadHost(ctx, dv); err != nil {
		slog.Error("Failed to create dead host", "error", err)
		h.setFlash(w, r, "error", "Failed to create 404 host: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "404 host created")
	}
	http.Redirect(w, r, "/proxy/dead-hosts", http.StatusSeeOther)
}

func (h *Handler) DeadDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	proxySvc := h.services.Proxy()
	if proxySvc == nil {
		w.Header().Set("HX-Trigger", `{"showToast":{"message":"Proxy service not configured","type":"error"}}`)
		w.WriteHeader(http.StatusOK)
		return
	}
	id, _ := strconv.Atoi(chi.URLParam(r, "id"))
	if err := proxySvc.DeleteDeadHost(ctx, id); err != nil {
		slog.Error("Failed to delete dead host", "error", err)
		w.Header().Set("HX-Trigger", `{"showToast":{"message":"Failed to delete 404 host: `+escapeJSON(err.Error())+`","type":"error"}}`)
		w.WriteHeader(http.StatusOK)
		return
	}
	w.Header().Set("HX-Trigger", `{"showToast":{"message":"404 host deleted","type":"success"}}`)
	w.Header().Set("HX-Redirect", "/proxy/dead-hosts")
	w.WriteHeader(http.StatusNoContent)
}

// ============================================================================
// Access Lists Handlers
// ============================================================================

func (h *Handler) ACLListTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Access Lists", "proxy")

	var connected bool
	var accessLists []proxy.ACLView

	if proxySvc := h.services.Proxy(); proxySvc != nil {
		connected = proxySvc.IsConnected(ctx)
		if connected {
			if list, err := proxySvc.ListAccessLists(ctx); err == nil {
				for _, al := range list {
					accessLists = append(accessLists, proxy.ACLView{
						ID:          al.ID,
						Name:        al.Name,
						SatisfyAny:  al.SatisfyAny,
						PassAuth:    al.PassAuth,
						ItemCount:   al.ItemCount,
						ClientCount: al.ClientCount,
					})
				}
			}
		}
	}

	data := proxy.ACLListData{
		PageData:    pageData,
		Connected:   connected,
		AccessLists: accessLists,
	}
	h.renderTempl(w, r, proxy.ACLList(data))
}

func (h *Handler) ACLNewTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "New Access List", "proxy")
	data := proxy.ACLFormData{PageData: pageData}
	h.renderTempl(w, r, proxy.ACLForm(data))
}

func (h *Handler) ACLCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	proxySvc := h.services.Proxy()
	if proxySvc == nil {
		h.setFlash(w, r, "error", "Proxy service not configured")
		http.Redirect(w, r, "/proxy/access-lists", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/proxy/access-lists/new", http.StatusSeeOther)
		return
	}

	av := parseACLForm(r)
	if err := proxySvc.CreateAccessList(ctx, av); err != nil {
		slog.Error("Failed to create access list", "error", err)
		h.setFlash(w, r, "error", "Failed to create access list: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Access list created")
	}
	http.Redirect(w, r, "/proxy/access-lists", http.StatusSeeOther)
}

func (h *Handler) ACLEditTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, _ := strconv.Atoi(chi.URLParam(r, "id"))
	pageData := h.prepareTemplPageData(r, "Edit Access List", "proxy")

	proxySvc := h.services.Proxy()
	if proxySvc == nil {
		h.setFlash(w, r, "error", "Proxy service not configured")
		http.Redirect(w, r, "/proxy/access-lists", http.StatusSeeOther)
		return
	}

	al, err := proxySvc.GetAccessList(ctx, id)
	if err != nil {
		h.setFlash(w, r, "error", "Access list not found")
		http.Redirect(w, r, "/proxy/access-lists", http.StatusSeeOther)
		return
	}

	templACL := &proxy.ACLView{
		ID:         al.ID,
		Name:       al.Name,
		SatisfyAny: al.SatisfyAny,
		PassAuth:   al.PassAuth,
	}

	var items []proxy.ACLItemView
	for _, item := range al.Items {
		items = append(items, proxy.ACLItemView{
			Username: item.Username,
			Password: item.Password,
		})
	}

	var clients []proxy.ACLClientView
	for _, c := range al.Clients {
		clients = append(clients, proxy.ACLClientView{
			Address: c.Address,
		})
	}

	data := proxy.ACLFormData{
		PageData: pageData,
		IsEdit:   true,
		ACL:      templACL,
		Items:    items,
		Clients:  clients,
	}
	h.renderTempl(w, r, proxy.ACLForm(data))
}

func (h *Handler) ACLUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	proxySvc := h.services.Proxy()
	if proxySvc == nil {
		h.setFlash(w, r, "error", "Proxy service not configured")
		http.Redirect(w, r, "/proxy/access-lists", http.StatusSeeOther)
		return
	}
	id, _ := strconv.Atoi(chi.URLParam(r, "id"))
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/proxy/access-lists", http.StatusSeeOther)
		return
	}

	av := parseACLForm(r)
	av.ID = id
	if err := proxySvc.UpdateAccessList(ctx, av); err != nil {
		slog.Error("Failed to update access list", "error", err)
		h.setFlash(w, r, "error", "Failed to update access list: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Access list updated")
	}
	http.Redirect(w, r, "/proxy/access-lists", http.StatusSeeOther)
}

func (h *Handler) ACLDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	proxySvc := h.services.Proxy()
	if proxySvc == nil {
		w.Header().Set("HX-Trigger", `{"showToast":{"message":"Proxy service not configured","type":"error"}}`)
		w.WriteHeader(http.StatusOK)
		return
	}
	id, _ := strconv.Atoi(chi.URLParam(r, "id"))
	if err := proxySvc.DeleteAccessList(ctx, id); err != nil {
		slog.Error("Failed to delete access list", "error", err)
		w.Header().Set("HX-Trigger", `{"showToast":{"message":"Failed to delete access list: `+escapeJSON(err.Error())+`","type":"error"}}`)
		w.WriteHeader(http.StatusOK)
		return
	}
	w.Header().Set("HX-Trigger", `{"showToast":{"message":"Access list deleted","type":"success"}}`)
	w.Header().Set("HX-Redirect", "/proxy/access-lists")
	w.WriteHeader(http.StatusNoContent)
}

// ============================================================================
// Audit Log Handler
// ============================================================================

func (h *Handler) AuditListTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Audit Log", "proxy")

	var connected bool
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	filter := r.URL.Query().Get("filter")
	perPage := 50
	offset := (page - 1) * perPage

	var logs []proxy.AuditLogView
	totalPages := 1

	if proxySvc := h.services.Proxy(); proxySvc != nil {
		connected = proxySvc.IsConnected(ctx)
		if connected {
			if auditLogs, total, err := proxySvc.ListAuditLogs(ctx, perPage, offset); err == nil {
				for _, l := range auditLogs {
					if filter != "" && l.Operation != filter {
						continue
					}
					logs = append(logs, proxy.AuditLogView{
						ID:           l.ID,
						Operation:    l.Operation,
						ResourceType: l.ResourceType,
						ResourceID:   l.ResourceID,
						ResourceName: l.ResourceName,
						UserName:     l.UserName,
						CreatedAt:    l.CreatedAt,
					})
				}
				totalPages = int(math.Ceil(float64(total) / float64(perPage)))
				if totalPages < 1 {
					totalPages = 1
				}
			}
		}
	}

	data := proxy.AuditListData{
		PageData:   pageData,
		Connected:  connected,
		Logs:       logs,
		Page:       page,
		TotalPages: totalPages,
		Filter:     filter,
	}
	h.renderTempl(w, r, proxy.AuditList(data))
}

// ============================================================================
// Helpers
// ============================================================================

func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func readFileOrText(r *http.Request, fileField, textField string) []byte {
	file, _, err := r.FormFile(fileField)
	if err == nil {
		defer file.Close()
		data, err := io.ReadAll(file)
		if err == nil && len(data) > 0 {
			return data
		}
	}
	text := r.FormValue(textField)
	if text != "" {
		return []byte(text)
	}
	return nil
}

func certViewToTempl(c CertificateView) proxy.CertView {
	daysLeft := 0
	isExpired := false
	expiresDisplay := c.ExpiresOn

	if c.ExpiresOn != "" {
		// Try parsing NPM date formats
		for _, layout := range []string{
			time.RFC3339,
			"2006-01-02T15:04:05.000Z",
			"2006-01-02 15:04:05",
		} {
			if t, err := time.Parse(layout, c.ExpiresOn); err == nil {
				daysLeft = int(time.Until(t).Hours() / 24)
				isExpired = daysLeft < 0
				expiresDisplay = t.Format("2006-01-02")
				break
			}
		}
	}

	return proxy.CertView{
		ID:          c.ID,
		NiceName:    c.NiceName,
		Provider:    c.Provider,
		DomainNames: c.DomainNames,
		ExpiresOn:   expiresDisplay,
		DaysLeft:    daysLeft,
		IsExpired:   isExpired,
	}
}

func parseACLForm(r *http.Request) *AccessListDetailView {
	av := &AccessListDetailView{
		Name:       r.FormValue("name"),
		SatisfyAny: r.FormValue("satisfy_any") == "on",
		PassAuth:   r.FormValue("pass_auth") == "on",
	}

	usernames := r.Form["auth_username[]"]
	passwords := r.Form["auth_password[]"]
	for i, u := range usernames {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		p := ""
		if i < len(passwords) {
			p = passwords[i]
		}
		av.Items = append(av.Items, AccessListItemView{Username: u, Password: p})
	}

	addresses := r.Form["client_address[]"]
	for _, addr := range addresses {
		addr = strings.TrimSpace(addr)
		if addr != "" {
			av.Clients = append(av.Clients, AccessListClientView{Address: addr, Directive: "allow"})
		}
	}

	return av
}
