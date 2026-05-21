// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"bytes"
	"encoding/json"
	"sync"

	"github.com/gorilla/websocket"
)

// wsJSONEncoder pairs a recyclable bytes.Buffer with the json.Encoder
// that targets it. Pooling the pair (rather than just the buffer) lets
// hot WebSocket write paths — pty → browser in the nvim editor, ssh
// stdout/stderr → browser in the terminal handler — reuse both the
// output buffer and the encoder across calls, dropping the per-frame
// json.Marshal allocation that ws.WriteJSON would otherwise incur.
type wsJSONEncoder struct {
	buf bytes.Buffer
	enc *json.Encoder
}

// wsJSONEncoderPool recycles encoding state across every WebSocket
// handler that emits JSON-framed text messages on a hot loop. Initial
// capacity matches the typical pty read buffer (4 KiB) plus the small
// fixed-name overhead, so the typical message fits without a Grow on
// the buffer's underlying slice.
var wsJSONEncoderPool = sync.Pool{
	New: func() any {
		st := &wsJSONEncoder{}
		st.buf.Grow(4*1024 + 128)
		st.enc = json.NewEncoder(&st.buf)
		return st
	},
}

// writeWSJSON encodes msg as JSON and writes it as a text WebSocket
// frame on conn. Output is byte-identical to ws.WriteJSON (i.e.
// json.Marshal + WriteMessage): the trailing '\n' that json.Encoder
// appends is trimmed before WriteMessage, so the wire payload matches
// what the browser-side decoder has historically received. The caller
// owns any mutex serialising writes to conn.
func writeWSJSON(conn *websocket.Conn, msg any) error {
	st := wsJSONEncoderPool.Get().(*wsJSONEncoder)
	st.buf.Reset()
	defer wsJSONEncoderPool.Put(st)

	data, err := encodeWSJSONInto(st, msg)
	if err != nil {
		return err
	}
	return conn.WriteMessage(websocket.TextMessage, data)
}

// encodeWSJSONInto writes msg as JSON into st.buf using the encoder
// bound to it, then returns the byte slice with the trailing newline
// (added by json.Encoder.Encode) trimmed. The returned slice aliases
// st.buf; callers must not retain it after returning st to the pool.
//
// Split out so the encode step is testable without spinning up a real
// websocket.Conn.
func encodeWSJSONInto(st *wsJSONEncoder, msg any) ([]byte, error) {
	if err := st.enc.Encode(msg); err != nil {
		return nil, err
	}
	data := st.buf.Bytes()
	if n := len(data); n > 0 && data[n-1] == '\n' {
		data = data[:n-1]
	}
	return data, nil
}
