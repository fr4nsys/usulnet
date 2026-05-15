// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package route53_test

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/services/dns"
	"github.com/fr4nsys/usulnet/internal/services/dns/providers/route53"
)

// fakeRoute53 emulates the wire surface route53 SDK calls:
//   - GET /2013-04-01/hostedzonesbyname
//   - POST /2013-04-01/hostedzone/Z123/rrset
type fakeRoute53 struct {
	t           *testing.T
	srv         *httptest.Server
	changeCalls int
	failNext    bool
}

func newFakeRoute53(t *testing.T) *fakeRoute53 {
	t.Helper()
	f := &fakeRoute53{t: t}
	mux := http.NewServeMux()
	mux.HandleFunc("/2013-04-01/hostedzonesbyname", f.handleListByName)
	mux.HandleFunc("/2013-04-01/hostedzone/", f.handleHostedZone)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		f.t.Logf("unmatched: %s %s", r.Method, r.URL.Path)
		http.Error(w, "not found", http.StatusNotFound)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeRoute53) handleListByName(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("dnsname")
	w.Header().Set("Content-Type", "application/xml")
	switch name {
	case "example.com.":
		fmt.Fprint(w, `<ListHostedZonesByNameResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
<HostedZones>
<HostedZone>
<Id>/hostedzone/Z123</Id>
<Name>example.com.</Name>
<CallerReference>test</CallerReference>
<Config><PrivateZone>false</PrivateZone></Config>
<ResourceRecordSetCount>2</ResourceRecordSetCount>
</HostedZone>
</HostedZones>
<DNSName>example.com.</DNSName>
<IsTruncated>false</IsTruncated>
<MaxItems>1</MaxItems>
</ListHostedZonesByNameResponse>`)
	default:
		fmt.Fprint(w, `<ListHostedZonesByNameResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
<HostedZones></HostedZones>
<DNSName>`+name+`</DNSName>
<IsTruncated>false</IsTruncated>
<MaxItems>1</MaxItems>
</ListHostedZonesByNameResponse>`)
	}
}

func (f *fakeRoute53) handleHostedZone(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/xml")
	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/rrset"):
		f.changeCalls++
		if f.failNext {
			http.Error(w, `<ErrorResponse><Error><Code>InvalidChangeBatch</Code><Message>but it was not found</Message></Error></ErrorResponse>`, http.StatusBadRequest)
			return
		}
		fmt.Fprint(w, `<ChangeResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
<ChangeInfo><Id>/change/C123</Id><Status>PENDING</Status><SubmittedAt>2024-01-01T00:00:00Z</SubmittedAt></ChangeInfo>
</ChangeResourceRecordSetsResponse>`)
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/rrset"):
		fmt.Fprint(w, `<ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
<ResourceRecordSets>
<ResourceRecordSet>
<Name>app.example.com.</Name>
<Type>A</Type>
<TTL>300</TTL>
<ResourceRecords><ResourceRecord><Value>1.2.3.4</Value></ResourceRecord></ResourceRecords>
</ResourceRecordSet>
</ResourceRecordSets>
<IsTruncated>false</IsTruncated>
<MaxItems>100</MaxItems>
</ListResourceRecordSetsResponse>`)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func newPlugin(t *testing.T, endpoint string) dns.Provider {
	t.Helper()
	creds, _ := json.Marshal(route53.Credentials{
		AccessKeyID: "ASIATEST", SecretAccessKey: "test-secret",
	})
	cfg := map[string]any{
		"region":   "us-east-1",
		"endpoint": endpoint,
	}
	p, err := route53.Factory(context.Background(), creds, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRoute53_Capabilities(t *testing.T) {
	caps := route53.Capabilities()
	if caps.DisplayName == "" {
		t.Fatalf("missing display name")
	}
	if len(caps.CredentialFields) < 2 {
		t.Fatalf("expected credential fields")
	}
}

func TestRoute53_Factory_RejectsMissingKey(t *testing.T) {
	_, err := route53.Factory(context.Background(), []byte(`{}`), nil)
	if !stderrors.Is(err, dns.ErrInvalidCredentials) {
		t.Fatalf("expected invalid credentials, got %v", err)
	}
}

func TestRoute53_VerifyCredentials(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/2013-04-01/hostedzone", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprint(w, `<ListHostedZonesResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
<HostedZones></HostedZones>
<IsTruncated>false</IsTruncated>
<MaxItems>1</MaxItems>
</ListHostedZonesResponse>`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	p := newPlugin(t, srv.URL)
	if err := p.VerifyCredentials(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRoute53_CreateRecord_Upsert(t *testing.T) {
	f := newFakeRoute53(t)
	p := newPlugin(t, f.srv.URL)
	rec, err := p.CreateRecord(context.Background(), dns.ProviderRecord{
		Name: "app.example.com", Type: models.DNSRecordTypeA, Content: "1.2.3.4", TTL: 300,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rec.ID == "" {
		t.Fatalf("expected synthetic id, got empty")
	}
	if f.changeCalls != 1 {
		t.Fatalf("expected 1 change request, got %d", f.changeCalls)
	}
}

func TestRoute53_DeleteRecord_NotFoundMapped(t *testing.T) {
	f := newFakeRoute53(t)
	f.failNext = true
	p := newPlugin(t, f.srv.URL)
	err := p.DeleteRecord(context.Background(), "id", dns.ProviderRecord{
		Name: "app.example.com", Type: models.DNSRecordTypeA, Content: "1.2.3.4",
	})
	if !stderrors.Is(err, dns.ErrRecordNotFound) {
		t.Fatalf("expected ErrRecordNotFound, got %v", err)
	}
}

func TestRoute53_ListRecords(t *testing.T) {
	f := newFakeRoute53(t)
	p := newPlugin(t, f.srv.URL)
	recs, err := p.ListRecords(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
}

func TestRoute53_ZoneNotFound(t *testing.T) {
	f := newFakeRoute53(t)
	p := newPlugin(t, f.srv.URL)
	_, err := p.CreateRecord(context.Background(), dns.ProviderRecord{
		Name: "x.unknown.tld", Type: models.DNSRecordTypeA, Content: "1.1.1.1",
	})
	if !stderrors.Is(err, dns.ErrZoneNotFound) {
		t.Fatalf("expected zone not found, got %v", err)
	}
}
