// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package docker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/client"

	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ImageListOptions specifies options for listing images
type ImageListOptions struct {
	// All includes intermediate images
	All bool

	// Filters to apply (e.g., {"reference": ["nginx*"], "dangling": ["true"]})
	Filters map[string][]string
}

// ImagePullOptions specifies options for pulling images
type ImagePullOptions struct {
	// RegistryAuth is base64 encoded registry authentication
	RegistryAuth string

	// Platform specifies the platform (e.g., "linux/amd64")
	Platform string

	// All pulls all tagged images in the repository
	All bool
}

// RegistryAuth holds registry authentication credentials
type RegistryAuth struct {
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	Email         string `json:"email,omitempty"`
	ServerAddress string `json:"serveraddress,omitempty"`
	IdentityToken string `json:"identitytoken,omitempty"`
	RegistryToken string `json:"registrytoken,omitempty"`
}

// EncodeRegistryAuth encodes registry auth to base64
func EncodeRegistryAuth(auth RegistryAuth) (string, error) {
	jsonAuth, err := json.Marshal(auth)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(jsonAuth), nil
}

// ImageList returns a list of images
func (c *Client) ImageList(ctx context.Context, opts ImageListOptions) ([]Image, error) {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	// Build filters
	f := filters.NewArgs()
	for key, values := range opts.Filters {
		for _, v := range values {
			f.Add(key, v)
		}
	}

	listOpts := image.ListOptions{
		All:     opts.All,
		Filters: f,
	}

	images, err := c.cli.ImageList(ctx, listOpts)
	if err != nil {
		log.Error("Failed to list images", "error", err)
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to list images")
	}

	result := make([]Image, len(images))
	for i, img := range images {
		result[i] = ImageFromSummary(img)
	}

	log.Debug("Listed images", "count", len(result), "all", opts.All)
	return result, nil
}

// ImageGet returns detailed information about an image
func (c *Client) ImageGet(ctx context.Context, imageID string) (*ImageDetails, error) {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	inspect, _, err := c.cli.ImageInspectWithRaw(ctx, imageID)
	if err != nil {
		if client.IsErrNotFound(err) {
			return nil, errors.New(errors.CodeImageNotFound, "image not found").
				WithDetail("image_id", imageID)
		}
		log.Error("Failed to inspect image", "image_id", imageID, "error", err)
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to inspect image")
	}

	details := ImageFromInspect(inspect)
	return &details, nil
}

// ImagePull pulls an image from a registry with progress reporting
func (c *Client) ImagePull(ctx context.Context, ref string, opts ImagePullOptions) (<-chan PullProgress, error) {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	pullOpts := image.PullOptions{
		RegistryAuth: opts.RegistryAuth,
		Platform:     opts.Platform,
		All:          opts.All,
	}

	log.Info("Pulling image", "ref", ref, "platform", opts.Platform)

	reader, err := c.cli.ImagePull(ctx, ref, pullOpts)
	if err != nil {
		log.Error("Failed to pull image", "ref", ref, "error", err)
		return nil, errors.Wrap(err, errors.CodeImagePullFailed, "failed to pull image")
	}

	progressCh := make(chan PullProgress, 100)

	go func() {
		defer close(progressCh)
		defer reader.Close()

		decoder := json.NewDecoder(reader)
		for {
			var progress PullProgress
			if err := decoder.Decode(&progress); err != nil {
				if err != io.EOF {
					progressCh <- PullProgress{Error: err.Error()}
				}
				return
			}

			// Check for error in progress
			if progress.Error != "" {
				progressCh <- progress
				return
			}

			progressCh <- progress
		}
	}()

	return progressCh, nil
}

// ImagePullSync pulls an image synchronously (blocks until complete)
func (c *Client) ImagePullSync(ctx context.Context, ref string, opts ImagePullOptions) error {
	log := logger.FromContext(ctx)

	progressCh, err := c.ImagePull(ctx, ref, opts)
	if err != nil {
		return err
	}

	// Consume progress and check for errors
	for progress := range progressCh {
		if progress.Error != "" {
			return errors.New(errors.CodeImagePullFailed, progress.Error).
				WithDetail("ref", ref)
		}
	}

	log.Info("Image pulled successfully", "ref", ref)
	return nil
}

// ImagePush pushes an image to a registry
func (c *Client) ImagePush(ctx context.Context, ref string, registryAuth string) (<-chan PullProgress, error) {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	pushOpts := image.PushOptions{
		RegistryAuth: registryAuth,
	}

	log.Info("Pushing image", "ref", ref)

	reader, err := c.cli.ImagePush(ctx, ref, pushOpts)
	if err != nil {
		log.Error("Failed to push image", "ref", ref, "error", err)
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to push image")
	}

	progressCh := make(chan PullProgress, 100)

	go func() {
		defer close(progressCh)
		defer reader.Close()

		decoder := json.NewDecoder(reader)
		for {
			var progress PullProgress
			if err := decoder.Decode(&progress); err != nil {
				if err != io.EOF {
					progressCh <- PullProgress{Error: err.Error()}
				}
				return
			}

			if progress.Error != "" {
				progressCh <- progress
				return
			}

			progressCh <- progress
		}
	}()

	return progressCh, nil
}

// ImageRemove removes an image
func (c *Client) ImageRemove(ctx context.Context, imageID string, force bool, pruneChildren bool) ([]image.DeleteResponse, error) {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	deleted, err := c.cli.ImageRemove(ctx, imageID, image.RemoveOptions{
		Force:         force,
		PruneChildren: pruneChildren,
	})
	if err != nil {
		if client.IsErrNotFound(err) {
			return nil, errors.New(errors.CodeImageNotFound, "image not found").
				WithDetail("image_id", imageID)
		}
		log.Error("Failed to remove image", "image_id", imageID, "error", err)
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to remove image")
	}

	log.Info("Image removed", "image_id", imageID, "deleted", len(deleted))
	return deleted, nil
}

// ImageTag tags an image
func (c *Client) ImageTag(ctx context.Context, source, target string) error {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return errors.New(errors.CodeDockerConnection, "client is closed")
	}

	if err := c.cli.ImageTag(ctx, source, target); err != nil {
		if client.IsErrNotFound(err) {
			return errors.New(errors.CodeImageNotFound, "image not found").
				WithDetail("source", source)
		}
		log.Error("Failed to tag image", "source", source, "target", target, "error", err)
		return errors.Wrap(err, errors.CodeInternal, "failed to tag image")
	}

	log.Info("Image tagged", "source", source, "target", target)
	return nil
}

// ImagePrune removes unused images
func (c *Client) ImagePrune(ctx context.Context, dangling bool, pruneFilters map[string][]string) (uint64, []image.DeleteResponse, error) {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return 0, nil, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	f := filters.NewArgs()
	if dangling {
		f.Add("dangling", "true")
	}
	for key, values := range pruneFilters {
		for _, v := range values {
			f.Add(key, v)
		}
	}

	report, err := c.cli.ImagesPrune(ctx, f)
	if err != nil {
		log.Error("Failed to prune images", "error", err)
		return 0, nil, errors.Wrap(err, errors.CodeInternal, "failed to prune images")
	}

	log.Info("Images pruned", "deleted", len(report.ImagesDeleted), "space_reclaimed", report.SpaceReclaimed)
	return report.SpaceReclaimed, report.ImagesDeleted, nil
}

// ImageHistory returns the history of an image
func (c *Client) ImageHistory(ctx context.Context, imageID string) ([]image.HistoryResponseItem, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	history, err := c.cli.ImageHistory(ctx, imageID)
	if err != nil {
		if client.IsErrNotFound(err) {
			return nil, errors.New(errors.CodeImageNotFound, "image not found").
				WithDetail("image_id", imageID)
		}
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get image history")
	}

	return history, nil
}

// ImageSave exports images to a tar archive
func (c *Client) ImageSave(ctx context.Context, imageIDs []string) (io.ReadCloser, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	reader, err := c.cli.ImageSave(ctx, imageIDs)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to save images")
	}

	return reader, nil
}

// ImageLoad loads images from a tar archive
func (c *Client) ImageLoad(ctx context.Context, input io.Reader, quiet bool) (image.LoadResponse, error) {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return image.LoadResponse{}, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	resp, err := c.cli.ImageLoad(ctx, input, client.ImageLoadWithQuiet(quiet))
	if err != nil {
		log.Error("Failed to load images", "error", err)
		return image.LoadResponse{}, errors.Wrap(err, errors.CodeInternal, "failed to load images")
	}

	log.Info("Images loaded")
	return resp, nil
}

// ImageSearch searches for images in registries
func (c *Client) ImageSearch(ctx context.Context, term string, limit int, registryAuth string) ([]registry.SearchResult, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	searchOpts := registry.SearchOptions{
		Limit:        limit,
		RegistryAuth: registryAuth,
	}

	results, err := c.cli.ImageSearch(ctx, term, searchOpts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to search images")
	}

	return results, nil
}

// ImageImport imports images from a tarball
func (c *Client) ImageImport(ctx context.Context, source image.ImportSource, ref string, changes []string) (io.ReadCloser, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return nil, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	importOpts := image.ImportOptions{
		Changes: changes,
	}

	reader, err := c.cli.ImageImport(ctx, source, ref, importOpts)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to import image")
	}

	return reader, nil
}

// ImageBuild builds an image from a Dockerfile
func (c *Client) ImageBuild(ctx context.Context, buildContext io.Reader, opts types.ImageBuildOptions) (types.ImageBuildResponse, error) {
	log := logger.FromContext(ctx)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return types.ImageBuildResponse{}, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	resp, err := c.cli.ImageBuild(ctx, buildContext, opts)
	if err != nil {
		log.Error("Failed to build image", "tags", opts.Tags, "error", err)
		return types.ImageBuildResponse{}, errors.Wrap(err, errors.CodeInternal, "failed to build image")
	}

	log.Info("Image build started", "tags", opts.Tags)
	return resp, nil
}

// ImageExists checks if an image exists locally
func (c *Client) ImageExists(ctx context.Context, ref string) (bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return false, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	_, _, err := c.cli.ImageInspectWithRaw(ctx, ref)
	if err != nil {
		if client.IsErrNotFound(err) {
			return false, nil
		}
		return false, errors.Wrap(err, errors.CodeInternal, "failed to check image existence")
	}

	return true, nil
}

// ImageDigest returns the digest of an image
func (c *Client) ImageDigest(ctx context.Context, ref string) (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return "", errors.New(errors.CodeDockerConnection, "client is closed")
	}

	inspect, _, err := c.cli.ImageInspectWithRaw(ctx, ref)
	if err != nil {
		if client.IsErrNotFound(err) {
			return "", errors.New(errors.CodeImageNotFound, "image not found").
				WithDetail("ref", ref)
		}
		return "", errors.Wrap(err, errors.CodeInternal, "failed to get image digest")
	}

	// Return first digest if available
	if len(inspect.RepoDigests) > 0 {
		return inspect.RepoDigests[0], nil
	}

	// Return ID if no digest available
	return inspect.ID, nil
}

// ImageSize returns the size of an image
func (c *Client) ImageSize(ctx context.Context, ref string) (int64, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return 0, errors.New(errors.CodeDockerConnection, "client is closed")
	}

	inspect, _, err := c.cli.ImageInspectWithRaw(ctx, ref)
	if err != nil {
		if client.IsErrNotFound(err) {
			return 0, errors.New(errors.CodeImageNotFound, "image not found").
				WithDetail("ref", ref)
		}
		return 0, errors.Wrap(err, errors.CodeInternal, "failed to get image size")
	}

	return inspect.Size, nil
}
