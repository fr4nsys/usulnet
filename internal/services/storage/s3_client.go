// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package storage

import (
	"bytes"
	"context"
	"io"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
)

// s3Client implements S3Client using aws-sdk-go-v2.
type s3Client struct {
	client     *s3.Client
	presignCli *s3.PresignClient
}

// S3ClientConfig holds configuration for creating an S3 client.
type S3ClientConfig struct {
	Endpoint     string
	Region       string
	AccessKey    string
	SecretKey    string
	UsePathStyle bool
	UseSSL       bool
}

// NewS3Client creates a new S3 client from the given config.
func NewS3Client(ctx context.Context, cfg S3ClientConfig) (S3Client, error) {
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}

	var opts []func(*awsconfig.LoadOptions) error
	opts = append(opts, awsconfig.WithRegion(cfg.Region))

	if cfg.AccessKey != "" && cfg.SecretKey != "" {
		opts = append(opts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, ""),
		))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeStorageError, "failed to load AWS config")
	}

	var s3Opts []func(*s3.Options)

	if cfg.Endpoint != "" {
		endpoint := cfg.Endpoint
		if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
			if cfg.UseSSL {
				endpoint = "https://" + endpoint
			} else {
				endpoint = "http://" + endpoint
			}
		}
		s3Opts = append(s3Opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(endpoint)
		})
	}

	if cfg.UsePathStyle {
		s3Opts = append(s3Opts, func(o *s3.Options) {
			o.UsePathStyle = true
		})
	}

	client := s3.NewFromConfig(awsCfg, s3Opts...)

	return &s3Client{
		client:     client,
		presignCli: s3.NewPresignClient(client),
	}, nil
}

func (c *s3Client) Healthy(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := c.client.ListBuckets(ctx, &s3.ListBucketsInput{})
	return err == nil
}

func (c *s3Client) ListBuckets(ctx context.Context) ([]BucketInfo, error) {
	resp, err := c.client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeStorageError, "failed to list buckets")
	}
	out := make([]BucketInfo, 0, len(resp.Buckets))
	for _, b := range resp.Buckets {
		bi := BucketInfo{}
		if b.Name != nil {
			bi.Name = *b.Name
		}
		if b.CreationDate != nil {
			bi.CreatedAt = *b.CreationDate
		}
		out = append(out, bi)
	}
	return out, nil
}

func (c *s3Client) CreateBucket(ctx context.Context, name, region string) error {
	input := &s3.CreateBucketInput{Bucket: aws.String(name)}
	if region != "" && region != "us-east-1" {
		input.CreateBucketConfiguration = &s3types.CreateBucketConfiguration{
			LocationConstraint: s3types.BucketLocationConstraint(region),
		}
	}
	_, err := c.client.CreateBucket(ctx, input)
	if err != nil {
		return errors.Wrap(err, errors.CodeStorageError, "failed to create bucket")
	}
	return nil
}

func (c *s3Client) DeleteBucket(ctx context.Context, name string) error {
	_, err := c.client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(name)})
	if err != nil {
		return errors.Wrap(err, errors.CodeStorageError, "failed to delete bucket")
	}
	return nil
}

func (c *s3Client) BucketExists(ctx context.Context, name string) (bool, error) {
	_, err := c.client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(name)})
	if err != nil {
		if strings.Contains(err.Error(), "NotFound") || strings.Contains(err.Error(), "404") {
			return false, nil
		}
		return false, errors.Wrap(err, errors.CodeStorageError, "failed to check bucket")
	}
	return true, nil
}

func (c *s3Client) GetBucketVersioning(ctx context.Context, name string) (bool, error) {
	resp, err := c.client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: aws.String(name)})
	if err != nil {
		return false, errors.Wrap(err, errors.CodeStorageError, "failed to get bucket versioning")
	}
	return resp.Status == s3types.BucketVersioningStatusEnabled, nil
}

func (c *s3Client) SetBucketVersioning(ctx context.Context, name string, enabled bool) error {
	status := s3types.BucketVersioningStatusSuspended
	if enabled {
		status = s3types.BucketVersioningStatusEnabled
	}
	_, err := c.client.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{
		Bucket:                  aws.String(name),
		VersioningConfiguration: &s3types.VersioningConfiguration{Status: status},
	})
	if err != nil {
		return errors.Wrap(err, errors.CodeStorageError, "failed to set versioning")
	}
	return nil
}

func (c *s3Client) ListObjects(ctx context.Context, bucket, prefix, delimiter string, maxKeys int) (*ListObjectsResult, error) {
	if maxKeys <= 0 {
		maxKeys = 1000
	}
	input := &s3.ListObjectsV2Input{
		Bucket:  aws.String(bucket),
		MaxKeys: aws.Int32(int32(maxKeys)),
	}
	if prefix != "" {
		input.Prefix = aws.String(prefix)
	}
	if delimiter != "" {
		input.Delimiter = aws.String(delimiter)
	}

	resp, err := c.client.ListObjectsV2(ctx, input)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeStorageError, "failed to list objects")
	}

	result := &ListObjectsResult{
		Objects:        make([]models.StorageObject, 0, len(resp.Contents)),
		CommonPrefixes: make([]string, 0, len(resp.CommonPrefixes)),
	}
	if resp.IsTruncated != nil {
		result.IsTruncated = *resp.IsTruncated
	}
	if resp.NextContinuationToken != nil {
		result.NextMarker = *resp.NextContinuationToken
	}

	for _, obj := range resp.Contents {
		so := models.StorageObject{
			StorageClass: string(obj.StorageClass),
		}
		if obj.Key != nil {
			so.Key = *obj.Key
		}
		if obj.Size != nil {
			so.Size = *obj.Size
		}
		if obj.LastModified != nil {
			so.LastModified = *obj.LastModified
		}
		if obj.ETag != nil {
			so.ETag = *obj.ETag
		}
		result.Objects = append(result.Objects, so)
	}

	for _, cp := range resp.CommonPrefixes {
		if cp.Prefix != nil {
			result.CommonPrefixes = append(result.CommonPrefixes, *cp.Prefix)
		}
	}

	return result, nil
}

func (c *s3Client) GetObject(ctx context.Context, bucket, key string) (io.ReadCloser, *ObjectMeta, error) {
	resp, err := c.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, nil, errors.Wrap(err, errors.CodeStorageError, "failed to get object")
	}
	meta := &ObjectMeta{Key: key}
	if resp.ContentLength != nil {
		meta.ContentLength = *resp.ContentLength
	}
	if resp.LastModified != nil {
		meta.LastModified = *resp.LastModified
	}
	if resp.ETag != nil {
		meta.ETag = *resp.ETag
	}
	if resp.ContentType != nil {
		meta.ContentType = *resp.ContentType
	}
	return resp.Body, meta, nil
}

func (c *s3Client) PutObject(ctx context.Context, bucket, key string, reader io.Reader, size int64, contentType string) error {
	input := &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   reader,
	}
	if size > 0 {
		input.ContentLength = aws.Int64(size)
	}
	if contentType != "" {
		input.ContentType = aws.String(contentType)
	}
	_, err := c.client.PutObject(ctx, input)
	if err != nil {
		return errors.Wrap(err, errors.CodeStorageError, "failed to put object")
	}
	return nil
}

func (c *s3Client) DeleteObject(ctx context.Context, bucket, key string) error {
	_, err := c.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return errors.Wrap(err, errors.CodeStorageError, "failed to delete object")
	}
	return nil
}

func (c *s3Client) DeleteObjects(ctx context.Context, bucket string, keys []string) error {
	if len(keys) == 0 {
		return nil
	}
	objs := make([]s3types.ObjectIdentifier, len(keys))
	for i, k := range keys {
		objs[i] = s3types.ObjectIdentifier{Key: aws.String(k)}
	}
	_, err := c.client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
		Bucket: aws.String(bucket),
		Delete: &s3types.Delete{Objects: objs, Quiet: aws.Bool(true)},
	})
	if err != nil {
		return errors.Wrap(err, errors.CodeStorageError, "failed to delete objects")
	}
	return nil
}

func (c *s3Client) CopyObject(ctx context.Context, srcBucket, srcKey, dstBucket, dstKey string) error {
	_, err := c.client.CopyObject(ctx, &s3.CopyObjectInput{
		Bucket:     aws.String(dstBucket),
		Key:        aws.String(dstKey),
		CopySource: aws.String(srcBucket + "/" + srcKey),
	})
	if err != nil {
		return errors.Wrap(err, errors.CodeStorageError, "failed to copy object")
	}
	return nil
}

func (c *s3Client) PresignGetObject(ctx context.Context, bucket, key string, expiry time.Duration) (string, error) {
	if expiry == 0 {
		expiry = time.Hour
	}
	req, err := c.presignCli.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}, func(opts *s3.PresignOptions) { opts.Expires = expiry })
	if err != nil {
		return "", errors.Wrap(err, errors.CodeStorageError, "failed to presign GET")
	}
	return req.URL, nil
}

func (c *s3Client) PresignPutObject(ctx context.Context, bucket, key string, expiry time.Duration) (string, error) {
	if expiry == 0 {
		expiry = time.Hour
	}
	req, err := c.presignCli.PresignPutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}, func(opts *s3.PresignOptions) { opts.Expires = expiry })
	if err != nil {
		return "", errors.Wrap(err, errors.CodeStorageError, "failed to presign PUT")
	}
	return req.URL, nil
}

// CreateFolder creates a zero-byte folder marker.
func CreateFolder(ctx context.Context, client S3Client, bucket, prefix string) error {
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return client.PutObject(ctx, bucket, prefix, bytes.NewReader(nil), 0, "application/x-directory")
}
