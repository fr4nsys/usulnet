// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package route53 implements the AWS Route 53 DNS provider plugin.
// We use the AWS SDK v2 (already a transitive dep via S3) so SigV4
// signing and retry logic come for free; reimplementing them by hand
// would dwarf the rest of this file.
package route53

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	r53 "github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/smithy-go"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/services/dns"
)

// Capabilities returns the plugin's static metadata.
func Capabilities() dns.Capabilities {
	return dns.Capabilities{
		DisplayName: "AWS Route 53",
		Description: "AWS Route 53 hosted zones via the AWS SDK. Requires an IAM access key with route53:ChangeResourceRecordSets and ListHostedZones.",
		Records: []dns.SupportedRecord{
			{Type: models.DNSRecordTypeA, Read: true, Write: true, UpdateTTL: true},
			{Type: models.DNSRecordTypeAAAA, Read: true, Write: true, UpdateTTL: true},
			{Type: models.DNSRecordTypeCNAME, Read: true, Write: true, UpdateTTL: true},
			{Type: models.DNSRecordTypeMX, Read: true, Write: true, UpdateTTL: true},
			{Type: models.DNSRecordTypeTXT, Read: true, Write: true, UpdateTTL: true},
			{Type: models.DNSRecordTypeNS, Read: true, Write: true, UpdateTTL: true},
			{Type: models.DNSRecordTypeSRV, Read: true, Write: true, UpdateTTL: true},
			{Type: models.DNSRecordTypeCAA, Read: true, Write: true, UpdateTTL: true},
			{Type: models.DNSRecordTypePTR, Read: true, Write: true, UpdateTTL: true},
		},
		CredentialFields: []dns.CredentialField{
			{Key: "access_key_id", Label: "AWS Access Key ID", Required: true, Secret: false},
			{Key: "secret_access_key", Label: "AWS Secret Access Key", Required: true, Secret: true},
			{Key: "session_token", Label: "AWS Session Token", Required: false, Secret: true,
				Description: "Only required for short-lived (STS) credentials."},
		},
		ConfigFields: []dns.ConfigField{
			{Key: "region", Label: "Region", Type: "string", Default: "us-east-1",
				Description: "Route 53 is global; this region is used for the SDK SigV4 endpoint resolver."},
			{Key: "endpoint", Label: "API endpoint override", Type: "string",
				Description: "Override for tests or AWS-compatible mock endpoints."},
		},
	}
}

// Credentials is the JSON shape stored encrypted at rest.
type Credentials struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token,omitempty"`
}

// Provider implements dns.Provider against AWS Route 53.
type Provider struct {
	client *r53.Client
}

// Factory builds a Provider.
func Factory(ctx context.Context, credentialsBlob []byte, config map[string]any) (dns.Provider, error) {
	var creds Credentials
	if err := json.Unmarshal(credentialsBlob, &creds); err != nil {
		return nil, fmt.Errorf("route53: invalid credentials JSON: %w", err)
	}
	if strings.TrimSpace(creds.AccessKeyID) == "" || strings.TrimSpace(creds.SecretAccessKey) == "" {
		return nil, fmt.Errorf("route53: %w: access_key_id and secret_access_key are required", dns.ErrInvalidCredentials)
	}
	region := "us-east-1"
	if v, ok := config["region"].(string); ok && v != "" {
		region = v
	}
	endpoint, _ := config["endpoint"].(string)

	awsCfg := aws.Config{
		Region:      region,
		Credentials: credentials.NewStaticCredentialsProvider(creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken),
		HTTPClient:  &http.Client{Timeout: 30 * time.Second},
	}
	opts := []func(*r53.Options){}
	if endpoint != "" {
		opts = append(opts, func(o *r53.Options) {
			o.BaseEndpoint = aws.String(endpoint)
		})
	}
	client := r53.NewFromConfig(awsCfg, opts...)
	return &Provider{client: client}, nil
}

// Register adds the plugin to the registry.
func Register(reg *dns.Registry) error {
	return reg.Register(models.DNSProviderKindRoute53, Factory, Capabilities())
}

// Kind returns the provider identifier.
func (p *Provider) Kind() models.DNSProviderKind { return models.DNSProviderKindRoute53 }

// Close is a no-op.
func (p *Provider) Close() error { return nil }

// VerifyCredentials calls ListHostedZones with MaxItems=1, the lowest-
// cost call that returns 401/403 for bad creds.
func (p *Provider) VerifyCredentials(ctx context.Context) error {
	maxItems := int32(1)
	_, err := p.client.ListHostedZones(ctx, &r53.ListHostedZonesInput{MaxItems: &maxItems})
	if err != nil {
		var apiErr smithy.APIError
		if stderrors.As(err, &apiErr) {
			switch apiErr.ErrorCode() {
			case "InvalidClientTokenId", "SignatureDoesNotMatch", "AccessDenied", "UnauthorizedOperation":
				return fmt.Errorf("%w: %s", dns.ErrInvalidCredentials, apiErr.ErrorMessage())
			}
		}
		return fmt.Errorf("route53: verify failed: %w", err)
	}
	return nil
}

// CreateRecord upserts a single record. Route 53's CreateChangeBatch
// is naturally upsert-friendly — we use UPSERT to keep idempotency.
func (p *Provider) CreateRecord(ctx context.Context, rec dns.ProviderRecord) (dns.ProviderRecord, error) {
	zoneID, err := p.findZoneID(ctx, rec.Name)
	if err != nil {
		return dns.ProviderRecord{}, err
	}
	rrset := buildRRSet(rec)
	_, err = p.client.ChangeResourceRecordSets(ctx, &r53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID),
		ChangeBatch: &types.ChangeBatch{
			Changes: []types.Change{{
				Action:            types.ChangeActionUpsert,
				ResourceRecordSet: &rrset,
			}},
		},
	})
	if err != nil {
		return dns.ProviderRecord{}, fmt.Errorf("route53: change record set: %w", err)
	}
	// Route 53's record id is the natural composite (name+type) since
	// there is no per-record id. Use that so DeleteRecord can rebuild
	// the rrset from the local row.
	return dns.ProviderRecord{
		ID:      naturalRecordID(rec.Name, rec.Type),
		Name:    rec.Name,
		Type:    rec.Type,
		Content: rec.Content,
		TTL:     rec.TTL,
	}, nil
}

// DeleteRecord issues a DELETE change. The provider record id is the
// composite "name|type" we synthesized at create time.
func (p *Provider) DeleteRecord(ctx context.Context, _ string, rec dns.ProviderRecord) error {
	zoneID, err := p.findZoneID(ctx, rec.Name)
	if err != nil {
		return err
	}
	rrset := buildRRSet(rec)
	_, err = p.client.ChangeResourceRecordSets(ctx, &r53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID),
		ChangeBatch: &types.ChangeBatch{
			Changes: []types.Change{{
				Action:            types.ChangeActionDelete,
				ResourceRecordSet: &rrset,
			}},
		},
	})
	if err != nil {
		var apiErr smithy.APIError
		if stderrors.As(err, &apiErr) {
			if apiErr.ErrorCode() == "InvalidChangeBatch" &&
				strings.Contains(apiErr.ErrorMessage(), "but it was not found") {
				return dns.ErrRecordNotFound
			}
		}
		return fmt.Errorf("route53: delete record: %w", err)
	}
	return nil
}

// ListRecords paginates through the hosted zone matching the supplied
// zone name and returns every record set.
func (p *Provider) ListRecords(ctx context.Context, zone string) ([]dns.ProviderRecord, error) {
	zoneID, err := p.findZoneID(ctx, zone)
	if err != nil {
		return nil, err
	}
	var (
		out      []dns.ProviderRecord
		nextName *string
		nextType types.RRType
	)
	for {
		input := &r53.ListResourceRecordSetsInput{HostedZoneId: aws.String(zoneID)}
		if nextName != nil {
			input.StartRecordName = nextName
			input.StartRecordType = nextType
		}
		resp, err := p.client.ListResourceRecordSets(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("route53: list rrsets: %w", err)
		}
		for _, rr := range resp.ResourceRecordSets {
			rec := flattenRRSet(rr)
			if rec != nil {
				out = append(out, *rec)
			}
		}
		if !resp.IsTruncated {
			break
		}
		nextName = resp.NextRecordName
		nextType = resp.NextRecordType
	}
	return out, nil
}

// ============================================================================
// Internal helpers
// ============================================================================

func (p *Provider) findZoneID(ctx context.Context, recordName string) (string, error) {
	name := strings.TrimSuffix(recordName, ".")
	for {
		if name == "" {
			return "", dns.ErrZoneNotFound
		}
		dnsName := name + "."
		out, err := p.client.ListHostedZonesByName(ctx, &r53.ListHostedZonesByNameInput{
			DNSName: aws.String(dnsName),
		})
		if err != nil {
			return "", fmt.Errorf("route53: list hosted zones by name: %w", err)
		}
		for _, hz := range out.HostedZones {
			if hz.Name != nil && strings.EqualFold(strings.TrimSuffix(*hz.Name, "."), name) && hz.Id != nil {
				// The Id from the API is "/hostedzone/Z123..."; the
				// API expects the bare value without the prefix in
				// most call sites.
				return strings.TrimPrefix(*hz.Id, "/hostedzone/"), nil
			}
		}
		idx := strings.Index(name, ".")
		if idx < 0 {
			return "", dns.ErrZoneNotFound
		}
		name = name[idx+1:]
	}
}

func buildRRSet(rec dns.ProviderRecord) types.ResourceRecordSet {
	value := rec.Content
	if rec.Type == models.DNSRecordTypeTXT {
		// Route 53 requires TXT values quoted with double quotes.
		if !strings.HasPrefix(value, `"`) {
			value = `"` + value + `"`
		}
	}
	ttl := int64(rec.TTL)
	return types.ResourceRecordSet{
		Name: aws.String(rec.Name),
		Type: types.RRType(string(rec.Type)),
		TTL:  &ttl,
		ResourceRecords: []types.ResourceRecord{
			{Value: aws.String(value)},
		},
	}
}

func flattenRRSet(rr types.ResourceRecordSet) *dns.ProviderRecord {
	if rr.Name == nil || len(rr.ResourceRecords) == 0 {
		return nil
	}
	rec := &dns.ProviderRecord{
		ID:   naturalRecordID(*rr.Name, models.DNSRecordType(string(rr.Type))),
		Name: *rr.Name,
		Type: models.DNSRecordType(string(rr.Type)),
	}
	if rr.TTL != nil {
		rec.TTL = int(*rr.TTL)
	}
	if rr.ResourceRecords[0].Value != nil {
		rec.Content = strings.Trim(*rr.ResourceRecords[0].Value, `"`)
	}
	return rec
}

func naturalRecordID(name string, typ models.DNSRecordType) string {
	return strings.ToLower(strings.TrimSuffix(name, ".")) + "|" + string(typ)
}

// Compile-time interface check.
var _ dns.Provider = (*Provider)(nil)
