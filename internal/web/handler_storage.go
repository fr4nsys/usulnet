// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"io"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	storagetmpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/storage"
)

// ============================================================================
// Template page handlers
// ============================================================================

// StorageTempl renders the storage connections list page.
func (h *Handler) StorageTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Storage()
	if svc == nil {
		h.RenderServiceNotConfigured(w, r, "S3 Storage", "minio")
		return
	}

	conns, err := svc.ListConnections(r.Context())
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Internal Error", err.Error())
		return
	}

	pageData := h.preparePageData(r, "Storage", "storage")

	data := storagetmpl.StorageListData{
		PageData:    ToTemplPageData(pageData),
		Connections: make([]storagetmpl.StorageConnectionData, 0, len(conns)),
	}
	for _, c := range conns {
		data.Connections = append(data.Connections, storagetmpl.StorageConnectionData{
			ID:           c.ID,
			Name:         c.Name,
			Endpoint:     c.Endpoint,
			Region:       c.Region,
			UsePathStyle: c.UsePathStyle,
			UseSSL:       c.UseSSL,
			IsDefault:    c.IsDefault,
			Status:       c.Status,
			StatusMsg:    c.StatusMsg,
			CreatedAt:    c.CreatedAt,
			LastChecked:  c.LastChecked,
			BucketCount:  c.BucketCount,
			TotalSize:    c.TotalSize,
			TotalObjects: c.TotalObjects,
		})
	}

	h.renderTempl(w, r, storagetmpl.ConnectionsList(data))
}

// StorageBucketsTempl renders the bucket list for a connection.
func (h *Handler) StorageBucketsTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Storage()
	if svc == nil {
		h.RenderServiceNotConfigured(w, r, "S3 Storage", "minio")
		return
	}

	connID := chi.URLParam(r, "connID")

	conn, err := svc.GetConnection(connID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "Connection not found")
		return
	}

	buckets, err := svc.ListBuckets(r.Context(), connID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Internal Error", err.Error())
		return
	}

	pageData := h.preparePageData(r, "Buckets - "+conn.Name, "storage")

	data := storagetmpl.StorageBucketsData{
		PageData: ToTemplPageData(pageData),
		Connection: storagetmpl.StorageConnectionData{
			ID:       conn.ID,
			Name:     conn.Name,
			Endpoint: conn.Endpoint,
			Region:   conn.Region,
			Status:   conn.Status,
		},
		Buckets: make([]storagetmpl.StorageBucketData, 0, len(buckets)),
	}
	for _, b := range buckets {
		data.Buckets = append(data.Buckets, storagetmpl.StorageBucketData{
			Name:        b.Name,
			Region:      b.Region,
			SizeBytes:   b.SizeBytes,
			SizeHuman:   b.SizeHuman,
			ObjectCount: b.ObjectCount,
			IsPublic:    b.IsPublic,
			Versioning:  b.Versioning,
			CreatedAt:   b.CreatedAt,
		})
	}

	h.renderTempl(w, r, storagetmpl.BucketsList(data))
}

// StorageBrowserTempl renders the object browser for a bucket.
func (h *Handler) StorageBrowserTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Storage()
	if svc == nil {
		h.RenderServiceNotConfigured(w, r, "S3 Storage", "minio")
		return
	}

	connID := chi.URLParam(r, "connID")
	bucket := chi.URLParam(r, "bucket")
	prefix := r.URL.Query().Get("prefix")

	conn, err := svc.GetConnection(connID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "Connection not found")
		return
	}

	objects, err := svc.ListObjects(r.Context(), connID, bucket, prefix)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Internal Error", err.Error())
		return
	}

	breadcrumbs := buildBreadcrumbs(prefix)
	pageData := h.preparePageData(r, bucket+" - Browse", "storage")

	data := storagetmpl.StorageBrowserData{
		PageData:       ToTemplPageData(pageData),
		ConnectionID:   connID,
		ConnectionName: conn.Name,
		Bucket:         bucket,
		Prefix:         prefix,
		Breadcrumbs:    make([]storagetmpl.BreadcrumbItem, 0, len(breadcrumbs)),
		Objects:        make([]storagetmpl.StorageObjectData, 0, len(objects)),
	}
	for _, bc := range breadcrumbs {
		data.Breadcrumbs = append(data.Breadcrumbs, storagetmpl.BreadcrumbItem{
			Label:  bc.Label,
			Prefix: bc.Prefix,
		})
	}
	for _, o := range objects {
		data.Objects = append(data.Objects, storagetmpl.StorageObjectData{
			Key:          o.Key,
			Name:         o.Name,
			Size:         o.Size,
			SizeHuman:    o.SizeHuman,
			LastModified: o.LastModified,
			ContentType:  o.ContentType,
			IsDir:        o.IsDir,
		})
	}

	h.renderTempl(w, r, storagetmpl.Browser(data))
}

// StorageAuditTempl renders audit log page for a connection.
func (h *Handler) StorageAuditTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Storage()
	if svc == nil {
		h.RenderServiceNotConfigured(w, r, "S3 Storage", "minio")
		return
	}

	connID := chi.URLParam(r, "connID")
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	limit := 50
	offset := (page - 1) * limit

	conn, err := svc.GetConnection(connID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "Connection not found")
		return
	}

	entries, total, err := svc.ListAuditLogs(r.Context(), connID, limit, offset)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Internal Error", err.Error())
		return
	}

	pageData := h.preparePageData(r, "Audit Log - "+conn.Name, "storage")

	data := storagetmpl.StorageAuditData{
		PageData:       ToTemplPageData(pageData),
		ConnectionID:   connID,
		ConnectionName: conn.Name,
		Entries:        make([]storagetmpl.StorageAuditEntryData, 0, len(entries)),
		Page:           page,
		TotalPages:     int((total + int64(limit) - 1) / int64(limit)),
	}
	for _, e := range entries {
		data.Entries = append(data.Entries, storagetmpl.StorageAuditEntryData{
			Action:       e.Action,
			ResourceType: e.ResourceType,
			ResourceName: e.ResourceName,
			UserID:       e.UserID,
			CreatedAt:    e.CreatedAt,
		})
	}

	h.renderTempl(w, r, storagetmpl.AuditLog(data))
}

// ============================================================================
// API action handlers
// ============================================================================

// StorageCreateConnection handles POST /storage/connections.
func (h *Handler) StorageCreateConnection(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Storage()
	if svc == nil {
		http.Error(w, "Storage not configured", http.StatusServiceUnavailable)
		return
	}

	name := r.FormValue("name")
	endpoint := r.FormValue("endpoint")
	region := r.FormValue("region")
	accessKey := r.FormValue("access_key")
	secretKey := r.FormValue("secret_key")
	usePathStyle := r.FormValue("use_path_style") == "on"
	useSSL := r.FormValue("use_ssl") == "on"
	isDefault := r.FormValue("is_default") == "on"
	userID := h.getCurrentUsername(r)

	_, err := svc.CreateConnection(r.Context(), name, endpoint, region, accessKey, secretKey, usePathStyle, useSSL, isDefault, userID)
	if err != nil {
		h.setFlash(w, r, "error", "Failed to create connection: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Connection created successfully")
	}

	http.Redirect(w, r, "/storage", http.StatusSeeOther)
}

// StorageDeleteConnection handles POST /storage/{connID}/delete.
func (h *Handler) StorageDeleteConnection(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Storage()
	if svc == nil {
		http.Error(w, "Storage not configured", http.StatusServiceUnavailable)
		return
	}

	connID := chi.URLParam(r, "connID")
	userID := h.getCurrentUsername(r)

	if err := svc.DeleteConnection(r.Context(), connID, userID); err != nil {
		h.setFlash(w, r, "error", "Failed to delete connection: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Connection deleted")
	}

	http.Redirect(w, r, "/storage", http.StatusSeeOther)
}

// StorageTestConnection handles POST /storage/{connID}/test.
func (h *Handler) StorageTestConnection(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Storage()
	if svc == nil {
		http.Error(w, "Storage not configured", http.StatusServiceUnavailable)
		return
	}

	connID := chi.URLParam(r, "connID")

	if err := svc.TestConnection(r.Context(), connID); err != nil {
		h.setFlash(w, r, "error", "Connection test failed: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Connection test passed")
	}

	http.Redirect(w, r, "/storage/"+connID+"/buckets", http.StatusSeeOther)
}

// StorageCreateBucket handles POST /storage/{connID}/buckets.
func (h *Handler) StorageCreateBucket(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Storage()
	if svc == nil {
		http.Error(w, "Storage not configured", http.StatusServiceUnavailable)
		return
	}

	connID := chi.URLParam(r, "connID")
	name := r.FormValue("name")
	region := r.FormValue("region")
	isPublic := r.FormValue("is_public") == "on"
	versioning := r.FormValue("versioning") == "on"
	userID := h.getCurrentUsername(r)

	if err := svc.CreateBucket(r.Context(), connID, name, region, isPublic, versioning, userID); err != nil {
		h.setFlash(w, r, "error", "Failed to create bucket: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Bucket '"+name+"' created")
	}

	http.Redirect(w, r, "/storage/"+connID+"/buckets", http.StatusSeeOther)
}

// StorageDeleteBucket handles POST /storage/{connID}/buckets/{bucket}/delete.
func (h *Handler) StorageDeleteBucket(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Storage()
	if svc == nil {
		http.Error(w, "Storage not configured", http.StatusServiceUnavailable)
		return
	}

	connID := chi.URLParam(r, "connID")
	bucket := chi.URLParam(r, "bucket")
	userID := h.getCurrentUsername(r)

	if err := svc.DeleteBucket(r.Context(), connID, bucket, userID); err != nil {
		h.setFlash(w, r, "error", "Failed to delete bucket: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Bucket '"+bucket+"' deleted")
	}

	http.Redirect(w, r, "/storage/"+connID+"/buckets", http.StatusSeeOther)
}

// StorageUploadObject handles POST /storage/{connID}/buckets/{bucket}/upload.
func (h *Handler) StorageUploadObject(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Storage()
	if svc == nil {
		http.Error(w, "Storage not configured", http.StatusServiceUnavailable)
		return
	}

	connID := chi.URLParam(r, "connID")
	bucket := chi.URLParam(r, "bucket")
	prefix := r.URL.Query().Get("prefix")
	userID := h.getCurrentUsername(r)

	if err := r.ParseMultipartForm(100 << 20); err != nil {
		h.setFlash(w, r, "error", "Upload too large (max 100 MB)")
		http.Redirect(w, r, buildBrowserURL(connID, bucket, prefix), http.StatusSeeOther)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		h.setFlash(w, r, "error", "No file provided")
		http.Redirect(w, r, buildBrowserURL(connID, bucket, prefix), http.StatusSeeOther)
		return
	}
	defer file.Close()

	key := prefix + header.Filename
	contentType := header.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	if err := svc.UploadObject(r.Context(), connID, bucket, key, io.Reader(file), header.Size, contentType, userID); err != nil {
		h.setFlash(w, r, "error", "Upload failed: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Uploaded '"+header.Filename+"'")
	}

	http.Redirect(w, r, buildBrowserURL(connID, bucket, prefix), http.StatusSeeOther)
}

// StorageDeleteObject handles POST /storage/{connID}/buckets/{bucket}/delete-object.
func (h *Handler) StorageDeleteObject(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Storage()
	if svc == nil {
		http.Error(w, "Storage not configured", http.StatusServiceUnavailable)
		return
	}

	connID := chi.URLParam(r, "connID")
	bucket := chi.URLParam(r, "bucket")
	key := r.FormValue("key")
	prefix := r.URL.Query().Get("prefix")
	userID := h.getCurrentUsername(r)

	if err := svc.DeleteObject(r.Context(), connID, bucket, key, userID); err != nil {
		h.setFlash(w, r, "error", "Delete failed: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Deleted '"+path.Base(key)+"'")
	}

	http.Redirect(w, r, buildBrowserURL(connID, bucket, prefix), http.StatusSeeOther)
}

// StorageCreateFolder handles POST /storage/{connID}/buckets/{bucket}/create-folder.
func (h *Handler) StorageCreateFolder(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Storage()
	if svc == nil {
		http.Error(w, "Storage not configured", http.StatusServiceUnavailable)
		return
	}

	connID := chi.URLParam(r, "connID")
	bucket := chi.URLParam(r, "bucket")
	prefix := r.URL.Query().Get("prefix")
	folderName := r.FormValue("folder_name")
	userID := h.getCurrentUsername(r)

	fullPrefix := prefix + folderName
	if err := svc.CreateFolder(r.Context(), connID, bucket, fullPrefix, userID); err != nil {
		h.setFlash(w, r, "error", "Failed to create folder: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Folder '"+folderName+"' created")
	}

	http.Redirect(w, r, buildBrowserURL(connID, bucket, prefix), http.StatusSeeOther)
}

// StorageDownloadObject handles GET /storage/{connID}/buckets/{bucket}/download.
func (h *Handler) StorageDownloadObject(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Storage()
	if svc == nil {
		http.Error(w, "Storage not configured", http.StatusServiceUnavailable)
		return
	}

	connID := chi.URLParam(r, "connID")
	bucket := chi.URLParam(r, "bucket")
	key := r.URL.Query().Get("key")

	url, err := svc.PresignDownload(r.Context(), connID, bucket, key)
	if err != nil {
		http.Error(w, "Failed to generate download URL: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// StoragePresignUpload handles GET /storage/{connID}/buckets/{bucket}/presign-upload.
func (h *Handler) StoragePresignUpload(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Storage()
	if svc == nil {
		http.Error(w, "Storage not configured", http.StatusServiceUnavailable)
		return
	}

	connID := chi.URLParam(r, "connID")
	bucket := chi.URLParam(r, "bucket")
	key := r.URL.Query().Get("key")

	url, err := svc.PresignUpload(r.Context(), connID, bucket, key)
	if err != nil {
		http.Error(w, "Failed to generate upload URL: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(url))
}

// ============================================================================
// Helpers
// ============================================================================

type storageBreadcrumb struct {
	Label  string
	Prefix string
}

func buildBrowserURL(connID, bucket, prefix string) string {
	u := "/storage/" + connID + "/buckets/" + bucket + "/browse"
	if prefix != "" {
		u += "?prefix=" + prefix
	}
	return u
}

func buildBreadcrumbs(prefix string) []storageBreadcrumb {
	if prefix == "" {
		return nil
	}
	parts := strings.Split(strings.TrimSuffix(prefix, "/"), "/")
	crumbs := make([]storageBreadcrumb, 0, len(parts))
	accumulated := ""
	for _, p := range parts {
		if p == "" {
			continue
		}
		accumulated += p + "/"
		crumbs = append(crumbs, storageBreadcrumb{Label: p, Prefix: accumulated})
	}
	return crumbs
}

// getCurrentUsername extracts the current user identifier from the request context.
func (h *Handler) getCurrentUsername(r *http.Request) string {
	user := GetUserFromContext(r.Context())
	if user != nil {
		return user.ID
	}
	return ""
}

// setFlash stores a flash message in the session for the next request.
func (h *Handler) setFlash(w http.ResponseWriter, r *http.Request, msgType, message string) {
	session, _ := h.sessionStore.Get(r, "usulnet_session")
	if session != nil {
		session.Values["flash"] = &FlashMessage{
			Type:    msgType,
			Message: message,
		}
		_ = h.sessionStore.Save(r, w, session)
	}
}
