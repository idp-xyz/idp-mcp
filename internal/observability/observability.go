// Package observability provides structured logging and W3C Trace Context handling. The gateway
// forwards a valid incoming traceparent to the upstream, or starts a new trace, so audit records,
// logs and upstream calls correlate on one trace id. Trace context is a correlator, never an
// authorization input.
package observability

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"regexp"
	"strings"
)

// NewLogger returns a JSON logger at the given level ("debug", "info", "warn", "error").
func NewLogger(w io.Writer, level string) *slog.Logger {
	var l slog.Level
	_ = l.UnmarshalText([]byte(strings.ToUpper(level)))
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: l}))
}

var traceparentRE = regexp.MustCompile(`^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$`)

// TraceContext is a parsed or freshly started W3C trace context.
type TraceContext struct {
	TraceID  string
	ParentID string
	Flags    string
	State    string // tracestate, forwarded verbatim when the parent was valid
}

// ParseOrStart validates traceparent (version 00, non-zero ids); if invalid or absent it starts a
// new trace and drops tracestate, as W3C Trace Context requires.
func ParseOrStart(traceparent, tracestate string) TraceContext {
	m := traceparentRE.FindStringSubmatch(strings.TrimSpace(traceparent))
	if m != nil && m[1] != "ff" && strings.Trim(m[2], "0") != "" && strings.Trim(m[3], "0") != "" {
		if len(tracestate) > 512 {
			tracestate = ""
		}
		return TraceContext{TraceID: m[2], ParentID: m[3], Flags: m[4], State: tracestate}
	}
	return TraceContext{TraceID: randomHex(16), ParentID: randomHex(8), Flags: "01"}
}

// Child returns the traceparent for a call made on behalf of this context (a new span id).
func (t TraceContext) Child() string { return "00-" + t.TraceID + "-" + randomHex(8) + "-" + t.Flags }

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
