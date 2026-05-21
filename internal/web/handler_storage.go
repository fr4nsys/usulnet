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
		h.RenderServiceNotConfigured(w, r, "Storage", "encryption_key")
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
		h.RenderServiceNotConfigured(w, r, "Storage", "encryption_key")
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
		h.RenderServiceNotConfigured(w, r, "Storage", "encryption_key")
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
		h.RenderServiceNotConfigured(w, r, "Storage", "encryption_key")
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
// Supports multiple storage types: s3, azure, gcs, b2, sftp, local.
// storageCreateConnectionForm pins the union of every storage
// provider's create-connection fields. storage_type drives a
// switch over the per-backend fields below; the validator
// constrains storage_type to the known set so an unknown value
// is rejected at the binding layer rather than after seven
// FormValue reads.
type storageCreateConnectionForm struct {
	StorageType      string `form:"storage_type" validate:"omitempty,oneof=s3 azure gcs b2 sftp local"`
	Name             string `form:"name" validate:"required"`
	IsDefault        bool   `form:"is_default"`
	Endpoint         string `form:"endpoint"`
	Region           string `form:"region"`
	AccessKey        string `form:"access_key"`
	SecretKey        string `form:"secret_key"`
	UsePathStyle     bool   `form:"use_path_style"`
	UseSSL           bool   `form:"use_ssl"`
	AzureAccountName string `form:"azure_account_name"`
	AzureAccountKey  string `form:"azure_account_key"`
	AzureContainer   string `form:"azure_container"`
	GCSProjectID     string `form:"gcs_project_id"`
	GCSBucket        string `form:"gcs_bucket"`
	GCSCredentials   string `form:"gcs_credentials"`
	B2KeyID          string `form:"b2_key_id"`
	B2AppKey         string `form:"b2_app_key"`
	B2Bucket         string `form:"b2_bucket"`
	SFTPHost         string `form:"sftp_host"`
	SFTPPort         string `form:"sftp_port"`
	SFTPUsername     string `form:"sftp_username"`
	SFTPPassword     string `form:"sftp_password"`
	SFTPPath         string `form:"sftp_path"`
	LocalPath        string `form:"local_path"`
}

func (h *Handler) StorageCreateConnection(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Storage()
	if svc == nil {
		http.Error(w, "Storage not configured", http.StatusServiceUnavailable)
		return
	}

	var form storageCreateConnectionForm
	if msg := BindForm(r, &form); msg != "" {
		h.setFlash(w, r, "error", msg)
		http.Redirect(w, r, "/storage", http.StatusSeeOther)
		return
	}

	storageType := form.StorageType
	if storageType == "" {
		storageType = "s3"
	}
	userID := h.getCurrentUsername(r)

	var err error
	switch storageType {
	case "s3":
		_, err = svc.CreateConnection(r.Context(), form.Name, form.Endpoint, form.Region, form.AccessKey, form.SecretKey, form.UsePathStyle, form.UseSSL, form.IsDefault, userID)
	case "azure":
		_, err = svc.CreateConnection(r.Context(), form.Name, form.AzureAccountName, form.AzureContainer, form.AzureAccountKey, "", false, true, form.IsDefault, userID)
	case "gcs":
		_, err = svc.CreateConnection(r.Context(), form.Name, form.GCSProjectID, form.GCSBucket, form.GCSCredentials, "", false, true, form.IsDefault, userID)
	case "b2":
		_, err = svc.CreateConnection(r.Context(), form.Name, form.B2Bucket, "", form.B2KeyID, form.B2AppKey, false, true, form.IsDefault, userID)
	case "sftp":
		endpoint := form.SFTPHost + ":" + form.SFTPPort
		_, err = svc.CreateConnection(r.Context(), form.Name, endpoint, form.SFTPPath, form.SFTPUsername, form.SFTPPassword, false, false, form.IsDefault, userID)
	case "local":
		_, err = svc.CreateConnection(r.Context(), form.Name, "localhost", form.LocalPath, "", "", false, false, form.IsDefault, userID)
	default:
		// The validator's oneof already rejects unknown values, but
		// keep the explicit guard as a belt-and-suspenders fallback
		// in case the enum gains a member without an arm here.
		h.setFlash(w, r, "error", "Unknown storage type: "+storageType)
		http.Redirect(w, r, "/storage", http.StatusSeeOther)
		return
	}

	if err != nil {
		h.setFlash(w, r, "error", "Failed to create connection: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Connection created successfully")
	}

	http.Redirect(w, r, "/storage", http.StatusSeeOther)
}

// storageUpdateConnectionForm captures the storage-connection PATCH
// inputs. Every field is a pointer so the service can distinguish
// "absent in form → leave alone" from "present in form → overwrite".
// String pointers go through nilIfEmpty so the previous behaviour
// (a present-but-empty input is treated as absent) is preserved.
type storageUpdateConnectionForm struct {
	Name         *string `form:"name"`
	Endpoint     *string `form:"endpoint"`
	Region       *string `form:"region"`
	AccessKey    *string `form:"access_key"`
	SecretKey    *string `form:"secret_key"`
	UsePathStyle *bool   `form:"use_path_style"`
	UseSSL       *bool   `form:"use_ssl"`
	IsDefault    *bool   `form:"is_default"`
}

// StorageUpdateConnection handles POST /storage/{connID}/update.
func (h *Handler) StorageUpdateConnection(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Storage()
	if svc == nil {
		http.Error(w, "Storage not configured", http.StatusServiceUnavailable)
		return
	}

	connID := chi.URLParam(r, "connID")
	userID := h.getCurrentUsername(r)

	var form storageUpdateConnectionForm
	if msg := BindForm(r, &form); msg != "" {
		h.setFlash(w, r, "error", msg)
		http.Redirect(w, r, "/storage", http.StatusSeeOther)
		return
	}

	if err := svc.UpdateConnection(r.Context(), connID,
		nilIfEmpty(form.Name),
		nilIfEmpty(form.Endpoint),
		nilIfEmpty(form.Region),
		nilIfEmpty(form.AccessKey),
		nilIfEmpty(form.SecretKey),
		form.UsePathStyle, form.UseSSL, form.IsDefault,
		userID); err != nil {
		h.setFlash(w, r, "error", "Failed to update connection: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Connection updated successfully")
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

// storageCreateBucketForm captures the bucket-create inputs.
type storageCreateBucketForm struct {
	Name       string `form:"name" validate:"required"`
	Region     string `form:"region"`
	IsPublic   bool   `form:"is_public"`
	Versioning bool   `form:"versioning"`
}

// StorageCreateBucket handles POST /storage/{connID}/buckets.
func (h *Handler) StorageCreateBucket(w http.ResponseWriter, r *http.Request) {
	svc := h.services.Storage()
	if svc == nil {
		http.Error(w, "Storage not configured", http.StatusServiceUnavailable)
		return
	}

	connID := chi.URLParam(r, "connID")
	var form storageCreateBucketForm
	if msg := BindForm(r, &form); msg != "" {
		h.setFlash(w, r, "error", msg)
		http.Redirect(w, r, "/storage/"+connID+"/buckets", http.StatusSeeOther)
		return
	}
	userID := h.getCurrentUsername(r)

	if err := svc.CreateBucket(r.Context(), connID, form.Name, form.Region, form.IsPublic, form.Versioning, userID); err != nil {
		h.setFlash(w, r, "error", "Failed to create bucket: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Bucket '"+form.Name+"' created")
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
	prefix := r.URL.Query().Get("prefix")
	userID := h.getCurrentUsername(r)

	var deleteForm struct {
		Key string `form:"key" validate:"required"`
	}
	if msg := BindForm(r, &deleteForm); msg != "" {
		h.setFlash(w, r, "error", msg)
		http.Redirect(w, r, buildBrowserURL(connID, bucket, prefix), http.StatusSeeOther)
		return
	}
	key := deleteForm.Key

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
	userID := h.getCurrentUsername(r)

	var folderForm struct {
		FolderName string `form:"folder_name" validate:"required"`
	}
	if msg := BindForm(r, &folderForm); msg != "" {
		h.setFlash(w, r, "error", msg)
		http.Redirect(w, r, buildBrowserURL(connID, bucket, prefix), http.StatusSeeOther)
		return
	}
	folderName := folderForm.FolderName

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
	if h == nil || h.sessionStore == nil {
		return
	}
	session, _ := h.sessionStore.Get(r, CookieSession)
	if session != nil {
		session.Values["flash"] = &FlashMessage{
			Type:    msgType,
			Message: message,
		}
		if err := h.sessionStore.Save(r, w, session); err != nil {
			h.logger.Warn("failed to save flash message to session", "error", err)
		}
	}
}
