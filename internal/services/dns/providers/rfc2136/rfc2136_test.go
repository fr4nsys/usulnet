// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package rfc2136_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	stderrors "errors"
	"net"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/services/dns"
	"github.com/fr4nsys/usulnet/internal/services/dns/providers/rfc2136"
)

// fakeUpdateServer is a minimal RFC 2136-aware DNS server that records
// inbound UPDATE messages. Tests assert on the recorded messages.
type fakeUpdateServer struct {
	t       *testing.T
	srv     *mdns.Server
	addr    string
	mu      sync.Mutex
	updates []*mdns.Msg
	rcode   int // override response rcode (0 = NOERROR)
}

func newFakeServer(t *testing.T, secret, keyName string) *fakeUpdateServer {
	t.Helper()
	f := &fakeUpdateServer{t: t}
	handler := mdns.HandlerFunc(func(w mdns.ResponseWriter, r *mdns.Msg) {
		f.t.Logf("fake server received message: opcode=%d question=%v tsigOK=%v",
			r.Opcode, r.Question, w.TsigStatus())
		f.mu.Lock()
		f.updates = append(f.updates, r)
		rcode := f.rcode
		f.mu.Unlock()

		resp := new(mdns.Msg)
		resp.SetReply(r)
		if rcode != 0 {
			resp.Rcode = rcode
		}
		// Mirror the inbound TSIG on the response so the client's
		// verifier accepts it (miekg/dns: the client's Exchange
		// rejects unsigned responses to signed requests).
		if t := r.IsTsig(); t != nil {
			resp.SetTsig(t.Hdr.Name, mdns.HmacSHA256, 300, time.Now().Unix())
		}
		_ = w.WriteMsg(resp)
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &mdns.Server{
		Addr:       listener.Addr().String(),
		Net:        "tcp",
		Handler:    handler,
		Listener:   listener,
		TsigSecret: map[string]string{mdns.Fqdn(keyName): secret},
		// Default MsgAcceptFunc rejects UPDATE messages with
		// NotImplemented — override so dynamic updates make it to
		// the handler.
		MsgAcceptFunc: func(dh mdns.Header) mdns.MsgAcceptAction {
			return mdns.MsgAccept
		},
	}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	f.srv = srv
	f.addr = listener.Addr().String()
	// Tiny wait so the server is accepting before tests connect.
	time.Sleep(10 * time.Millisecond)
	return f
}

func (f *fakeUpdateServer) lastUpdate() *mdns.Msg {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.updates) == 0 {
		return nil
	}
	return f.updates[len(f.updates)-1]
}

func newPlugin(t *testing.T, addr, key, secret string) dns.Provider {
	t.Helper()
	credsBytes, _ := json.Marshal(rfc2136.Credentials{
		TSIGKeyName: key, TSIGSecret: secret, TSIGAlgorithm: "hmac-sha256",
	})
	cfg := map[string]any{
		"nameserver":      addr,
		"zone":            "example.com.",
		"timeout_seconds": 5,
	}
	p, err := rfc2136.Factory(context.Background(), credsBytes, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRFC2136_Capabilities(t *testing.T) {
	caps := rfc2136.Capabilities()
	if caps.DisplayName == "" {
		t.Fatalf("missing display name")
	}
	if len(caps.CredentialFields) < 2 {
		t.Fatalf("expected credential fields")
	}
}

func TestRFC2136_Factory_RejectsMissingKey(t *testing.T) {
	_, err := rfc2136.Factory(context.Background(), []byte(`{}`), nil)
	if !stderrors.Is(err, dns.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestRFC2136_Factory_RejectsBadSecret(t *testing.T) {
	creds, _ := json.Marshal(rfc2136.Credentials{
		TSIGKeyName: "k.", TSIGSecret: "not-base64!!!",
	})
	_, err := rfc2136.Factory(context.Background(), creds, nil)
	if !stderrors.Is(err, dns.ErrInvalidCredentials) {
		t.Fatalf("expected invalid credentials, got %v", err)
	}
}

func TestRFC2136_Factory_RejectsUnknownAlgorithm(t *testing.T) {
	creds, _ := json.Marshal(rfc2136.Credentials{
		TSIGKeyName:   "k.",
		TSIGSecret:    base64.StdEncoding.EncodeToString([]byte("aaaaaaaaaaaa")),
		TSIGAlgorithm: "hmac-sha999",
	})
	_, err := rfc2136.Factory(context.Background(), creds, nil)
	if err == nil {
		t.Fatalf("expected error for unknown algorithm")
	}
}

func TestRFC2136_CreateAndDeleteRecord(t *testing.T) {
	keyName := "tsig-key."
	secret := base64.StdEncoding.EncodeToString([]byte("supersecretkeymaterial32bytes!!!"))
	srv := newFakeServer(t, secret, keyName)
	p := newPlugin(t, srv.addr, keyName, secret)

	rec := dns.ProviderRecord{
		Name:    "_acme-challenge.example.com",
		Type:    models.DNSRecordTypeTXT,
		Content: "challenge-value",
		TTL:     60,
	}
	out, err := p.CreateRecord(context.Background(), rec)
	if err != nil {
		t.Fatalf("CreateRecord: %v", err)
	}
	if out.ID == "" {
		t.Fatalf("expected id, got empty")
	}
	if u := srv.lastUpdate(); u == nil || u.Opcode != mdns.OpcodeUpdate {
		t.Fatalf("expected UPDATE message")
	}

	if err := p.DeleteRecord(context.Background(), out.ID, rec); err != nil {
		t.Fatalf("DeleteRecord: %v", err)
	}
}

func TestRFC2136_DeleteRecord_NXRRSetMappedToNotFound(t *testing.T) {
	keyName := "tsig-key."
	secret := base64.StdEncoding.EncodeToString([]byte("supersecretkeymaterial32bytes!!!"))
	srv := newFakeServer(t, secret, keyName)
	srv.rcode = mdns.RcodeNXRrset
	p := newPlugin(t, srv.addr, keyName, secret)
	rec := dns.ProviderRecord{Name: "x.example.com", Type: models.DNSRecordTypeTXT, Content: "v", TTL: 60}
	err := p.DeleteRecord(context.Background(), "anything", rec)
	if !stderrors.Is(err, dns.ErrRecordNotFound) {
		t.Fatalf("expected ErrRecordNotFound, got %v", err)
	}
}

func TestRFC2136_NotAuthMappedToInvalidCredentials(t *testing.T) {
	keyName := "tsig-key."
	secret := base64.StdEncoding.EncodeToString([]byte("supersecretkeymaterial32bytes!!!"))
	srv := newFakeServer(t, secret, keyName)
	srv.rcode = mdns.RcodeNotAuth
	p := newPlugin(t, srv.addr, keyName, secret)
	rec := dns.ProviderRecord{Name: "x.example.com", Type: models.DNSRecordTypeTXT, Content: "v", TTL: 60}
	_, err := p.CreateRecord(context.Background(), rec)
	if !stderrors.Is(err, dns.ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestRFC2136_ListRecords_Unsupported(t *testing.T) {
	keyName := "tsig-key."
	secret := base64.StdEncoding.EncodeToString([]byte("supersecretkeymaterial32bytes!!!"))
	srv := newFakeServer(t, secret, keyName)
	p := newPlugin(t, srv.addr, keyName, secret)
	if _, err := p.ListRecords(context.Background(), "example.com"); err == nil {
		t.Fatalf("expected ListRecords to return an unsupported error")
	}
}
