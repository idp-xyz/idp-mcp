// Package transport implements the parts of MCP Streamable HTTP (2026-07-28) the gateway and its
// upstream client share: bounded bodies, JSON-RPC response writing and SSE message parsing.
package transport

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"idp-mcp/internal/server"
)

// ErrTooLarge is returned when a body exceeds its limit.
var ErrTooLarge = errors.New("body exceeds limit")

// ReadBounded reads at most limit bytes and fails if there are more.
func ReadBounded(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, ErrTooLarge
	}
	return b, nil
}

// MediaType returns the lower-cased media type of a Content-Type value ("" if unparseable).
func MediaType(contentType string) string {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return ""
	}
	return strings.ToLower(mt)
}

// WriteJSON writes v as an application/json response that is never cached.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// WriteResult writes a JSON-RPC success response.
func WriteResult(w http.ResponseWriter, id json.RawMessage, result any) {
	WriteJSON(w, http.StatusOK, server.Response{JSONRPC: "2.0", ID: orNull(id), Result: result})
}

// WriteError writes a JSON-RPC error response with the given HTTP status.
func WriteError(w http.ResponseWriter, status int, id json.RawMessage, e *server.Error) {
	WriteJSON(w, status, server.Response{JSONRPC: "2.0", ID: orNull(id), Error: e})
}

// WriteRejection writes an admission rejection.
func WriteRejection(w http.ResponseWriter, r *server.Rejection) {
	WriteError(w, r.HTTPStatus, r.ID, r.Err)
}

func orNull(id json.RawMessage) json.RawMessage {
	if len(id) == 0 {
		return server.NullID
	}
	return id
}

// ParseMessage returns the single JSON-RPC message of an upstream response, which is either
// application/json or an SSE stream carrying exactly one message (non-message events ignored).
func ParseMessage(contentType string, body []byte) (json.RawMessage, error) {
	switch MediaType(contentType) {
	case "application/json":
		if !json.Valid(body) {
			return nil, errors.New("invalid JSON body")
		}
		return json.RawMessage(bytes.TrimSpace(body)), nil
	case "text/event-stream":
		var msgs []json.RawMessage
		for _, ev := range parseSSE(body) {
			if ev.event != "" && ev.event != "message" {
				continue
			}
			if !json.Valid([]byte(ev.data)) {
				return nil, errors.New("invalid JSON in SSE data")
			}
			msgs = append(msgs, json.RawMessage(ev.data))
		}
		if len(msgs) != 1 {
			return nil, errors.New("expected exactly one JSON-RPC message in the event stream")
		}
		return msgs[0], nil
	default:
		return nil, errors.New("unexpected content type " + contentType)
	}
}

type sseEvent struct{ event, data string }

func parseSSE(body []byte) []sseEvent {
	var out []sseEvent
	var cur sseEvent
	var data []string
	flush := func() {
		if len(data) > 0 {
			cur.data = strings.Join(data, "\n")
			out = append(out, cur)
		}
		cur, data = sseEvent{}, nil
	}
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 64*1024), 8<<20)
	for sc.Scan() {
		line := strings.TrimSuffix(sc.Text(), "\r")
		switch {
		case line == "":
			flush()
		case strings.HasPrefix(line, ":"):
		case strings.HasPrefix(line, "data:"):
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		case strings.HasPrefix(line, "event:"):
			cur.event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		}
	}
	flush()
	return out
}
