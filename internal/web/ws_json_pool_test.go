// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// newTestEncoder returns a wsJSONEncoder ready for use, matching what
// wsJSONEncoderPool.New produces. Used by tests to avoid hitting the live
// pool from parallel test runs.
func newTestEncoder() *wsJSONEncoder {
	st := &wsJSONEncoder{}
	st.buf.Grow(4*1024 + 128)
	st.enc = json.NewEncoder(&st.buf)
	return st
}

// TestEncodeWSJSONInto_ByteIdenticalToJSONMarshal pins the pool-based
// encoder's output against the json.Marshal output it replaced — and
// against ws.WriteJSON's wire format for the SSH terminal handler. The
// wire format must not drift; any divergence here would change what the
// browser-side decoder receives in either the editor or the SSH terminal.
func TestEncodeWSJSONInto_ByteIdenticalToJSONMarshal(t *testing.T) {
	cases := []struct {
		name string
		msg  any
	}{
		// nvim editor message shape
		{"editor_output_plain", wsEditorMsg{Type: "output", Data: "hello world"}},
		{"editor_output_empty_data", wsEditorMsg{Type: "output", Data: ""}},
		{"editor_output_with_newlines", wsEditorMsg{Type: "output", Data: "line1\nline2\nline3"}},
		{"editor_output_with_ansi_escape", wsEditorMsg{Type: "output", Data: "\x1b[1;32mok\x1b[0m"}},
		{"editor_output_with_quote_and_backslash", wsEditorMsg{Type: "output", Data: `say "hi" \backslash`}},
		{"editor_output_with_html_chars", wsEditorMsg{Type: "output", Data: `<div>&amp;</div>`}},
		{"editor_output_with_unicode", wsEditorMsg{Type: "output", Data: "héllo — 文字"}},
		{"editor_output_with_controls", wsEditorMsg{Type: "output", Data: "tab\there\nnewline"}},
		{"editor_output_4k_payload", wsEditorMsg{Type: "output", Data: strings.Repeat("x", 4096)}},
		{"editor_error_message", wsEditorMsg{Type: "error", Data: "boom: file not found"}},
		{"editor_committed_path", wsEditorMsg{Type: "committed", Data: "/var/x/y.txt"}},
		{"editor_resize_only", wsEditorMsg{Type: "resize", Cols: 120, Rows: 40}},

		// SSH terminal message shape — different field set (Field / Username /
		// Password) so this guards against any shape-specific assumption inside
		// the encoder.
		{"ssh_output_plain", SSHTerminalMessage{Type: "output", Data: "hello"}},
		{"ssh_output_ansi", SSHTerminalMessage{Type: "output", Data: "\x1b[31merr\x1b[0m"}},
		{"ssh_output_4k", SSHTerminalMessage{Type: "output", Data: strings.Repeat("y", 4096)}},
		{"ssh_resize", SSHTerminalMessage{Type: "resize", Cols: 100, Rows: 30}},
		{"ssh_credential_request", SSHTerminalMessage{Type: "credential_request", Field: "password"}},
		{"ssh_connected_event", SSHTerminalMessage{Type: "connected", Data: "ok"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			want, err := json.Marshal(c.msg)
			if err != nil {
				t.Fatalf("json.Marshal baseline failed: %v", err)
			}

			st := newTestEncoder()
			got, err := encodeWSJSONInto(st, c.msg)
			if err != nil {
				t.Fatalf("encodeWSJSONInto failed: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("byte mismatch\n want: %q\n  got: %q", want, got)
			}
		})
	}
}

// TestEncodeWSJSONInto_TrimsTrailingNewline guards the one behavioral
// difference between json.Encoder.Encode (which appends '\n') and
// json.Marshal (which does not). The trim must run, otherwise every
// message ships one extra byte to the browser.
func TestEncodeWSJSONInto_TrimsTrailingNewline(t *testing.T) {
	st := newTestEncoder()
	got, err := encodeWSJSONInto(st, wsEditorMsg{Type: "x", Data: "y"})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if n := len(got); n == 0 || got[n-1] == '\n' {
		t.Fatalf("trailing newline not trimmed: %q", got)
	}
}

// TestEncodeWSJSONInto_ReusedBuffer asserts the encoder works correctly
// when a wsJSONEncoder is recycled (the sync.Pool pattern). After the
// first encode the buffer is non-empty; the second encode must reset
// cleanly and not leak the first message's bytes into the second output.
func TestEncodeWSJSONInto_ReusedBuffer(t *testing.T) {
	st := newTestEncoder()
	if _, err := encodeWSJSONInto(st, wsEditorMsg{Type: "output", Data: "first"}); err != nil {
		t.Fatalf("first encode: %v", err)
	}
	// Caller's responsibility: reset the buffer before reusing the state
	// (matches writeWSJSON's pool.Get + buf.Reset pattern).
	st.buf.Reset()
	got, err := encodeWSJSONInto(st, wsEditorMsg{Type: "output", Data: "second"})
	if err != nil {
		t.Fatalf("second encode: %v", err)
	}
	want, _ := json.Marshal(wsEditorMsg{Type: "output", Data: "second"})
	if !bytes.Equal(got, want) {
		t.Fatalf("recycled buffer produced wrong output\n want: %q\n  got: %q", want, got)
	}
	if bytes.Contains(got, []byte("first")) {
		t.Fatalf("recycled buffer leaked previous payload: %q", got)
	}
}

// TestEncodeWSJSONInto_AcrossMessageShapes asserts that the same
// recycled encoder can encode different concrete message types back-to-back
// without state bleeding between them. Both the editor and the SSH
// terminal share the global wsJSONEncoderPool, so this is the recycling
// path that gets hit in production whenever both handlers are active in
// the same process.
func TestEncodeWSJSONInto_AcrossMessageShapes(t *testing.T) {
	st := newTestEncoder()

	if _, err := encodeWSJSONInto(st, wsEditorMsg{Type: "output", Data: "editor"}); err != nil {
		t.Fatalf("editor encode: %v", err)
	}
	st.buf.Reset()
	got, err := encodeWSJSONInto(st, SSHTerminalMessage{Type: "output", Data: "ssh"})
	if err != nil {
		t.Fatalf("ssh encode: %v", err)
	}
	want, _ := json.Marshal(SSHTerminalMessage{Type: "output", Data: "ssh"})
	if !bytes.Equal(got, want) {
		t.Fatalf("cross-shape recycle wrong\n want: %q\n  got: %q", want, got)
	}
}

// BenchmarkWSJSONEncode_Pooled measures the per-message cost of the
// pool-backed encoder. With the sync.Pool in place, once the pool is
// warm repeated calls should report a single small alloc (the json
// package's internal encodeState, also pooled by encoding/json) vs.
// the two-alloc, ~5 KiB-output baseline that json.Marshal pays.
func BenchmarkWSJSONEncode_Pooled(b *testing.B) {
	msg := wsEditorMsg{Type: "output", Data: strings.Repeat("x", 4096)}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		st := wsJSONEncoderPool.Get().(*wsJSONEncoder)
		st.buf.Reset()
		_, err := encodeWSJSONInto(st, msg)
		if err != nil {
			b.Fatal(err)
		}
		wsJSONEncoderPool.Put(st)
	}
}

// BenchmarkWSJSONEncode_JSONMarshalBaseline runs the path the pooled
// encoder replaced — a fresh json.Marshal on every call — so the alloc
// and ns/op reduction reported by `go test -bench` is directly
// attributable to the pool.
func BenchmarkWSJSONEncode_JSONMarshalBaseline(b *testing.B) {
	msg := wsEditorMsg{Type: "output", Data: strings.Repeat("x", 4096)}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := json.Marshal(msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}
