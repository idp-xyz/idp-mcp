package gateway

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"idp-mcp/internal/invocation"
	"idp-mcp/internal/release"
	"idp-mcp/internal/server"
	"idp-mcp/internal/transport"
)

// What the gateway does for a target of class external (ADR-0001 D51). A server that is not ours is untrusted in
// both directions: nothing about the caller goes to it beyond what it needs to function, and nothing it sends back is
// taken for more than data. This file holds the two halves: externalParams for what is sent, and relayExternal for
// what comes back.

// MetaProgressToken is the key of the progress token in a request's _meta (MCP, "progress").
const MetaProgressToken = "progressToken"

// maxProgressToken bounds the progress token, a value the client makes up and the upstream must repeat.
const maxProgressToken = 128

// targetByEndpoint returns the target of the release that owns endpoint.
func targetByEndpoint(doc *release.Document, endpoint string) *release.Target {
	for i := range doc.Targets {
		if doc.Targets[i].Endpoint == endpoint {
			return &doc.Targets[i]
		}
	}
	return nil
}

// externalParams returns the params the gateway sends to a target of class external, and the progress token it
// sent (nil if none): the client's params with a _meta made by the gateway from an allow-list, not cleaned of
// what is unwanted, so that a key nobody thought of is not sent either. The allow-list, with the reason for each key:
//
//   - io.modelcontextprotocol/protocolVersion: the envelope of every 2026-07-28 request; the server cannot answer
//     without it. The gateway's own value, not the client's.
//   - io.modelcontextprotocol/clientCapabilities: the envelope's other required key. Always the empty object:
//     the client's capabilities (sampling, elicitation, extensions) are what a server would use to ask for more, and the
//     gateway relays nothing of the kind from an external server.
//   - progressToken: the token with which the server reports progress of this call; opaque, bounded, and a
//     string or an integer. Without it a long call shows no progress.
//
// Dropped, by omission: clientInfo (which program and version the caller runs), the gateway's caller keys, the
// W3C trace keys, and every key a client or an intermediary invented. The top-level params that continue a
// multi-round flow (inputResponses, requestState) or ask for a task are dropped too: an external server is never
// given a reason to answer with either, and a client that sends them is not served by it. The caller is not
// forwarded whatever the target's identity mode says (D51 a), because this function does not look at the mode.
func externalParams(params map[string]json.RawMessage) (map[string]json.RawMessage, json.RawMessage) {
	out := make(map[string]json.RawMessage, len(params))
	for k, v := range params {
		switch k {
		case "_meta", "inputResponses", "requestState", "task":
		default:
			out[k] = v
		}
	}
	protocol, _ := json.Marshal(server.ProtocolVersion)
	meta := map[string]json.RawMessage{
		server.MetaProtocolVersion:    protocol,
		server.MetaClientCapabilities: json.RawMessage(`{}`),
	}
	var token json.RawMessage
	var in map[string]json.RawMessage
	if json.Unmarshal(params["_meta"], &in) == nil {
		if t, ok := in[MetaProgressToken]; ok && validProgressToken(t) {
			token = t
			meta[MetaProgressToken] = t
		}
	}
	out["_meta"], _ = json.Marshal(meta)
	return out, token
}

// validProgressToken accepts a string of at most maxProgressToken bytes or an integer.
func validProgressToken(raw json.RawMessage) bool {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return len(s) <= maxProgressToken && !strings.ContainsAny(s, "\x00\r\n")
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil && len(n) < 20 {
		_, err := n.Int64()
		return err == nil
	}
	return false
}

// toolErrorResult is the answer a client gets, as a tool error it can read, when the gateway ends a call to an
// external target: not a protocol error, which a client treats as a fault of its own request.
func (g *Gateway) toolErrorResult(id json.RawMessage, text string) server.Response {
	return server.Response{JSONRPC: "2.0", ID: id, Result: server.Complete(map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}}, "isError": true}, g.cfg.Info)}
}

// reverseMethods names the requests a server may send to a client; only these are put in the audit, so that a
// method name an upstream made up is not.
var reverseMethods = map[string]bool{"sampling/createMessage": true, "elicitation/create": true, "roots/list": true, "ping": true}

func reverseReason(method string) string {
	if !reverseMethods[method] {
		method = "an unknown method"
	}
	return "the server sent the client a request (" + method + "); a server of class external may not ask the client for anything"
}

// verdict of one message of an external server's answer.
type verdict int

const (
	vFinal    verdict = iota // the response to this request
	vProgress                // a progress notification for this call's token
	vDrop                    // a notification that is not relayed
	vReverse                 // a request from the server to the client, or a result that asks for one
	vBad                     // not a message of this call
)

// classify says what a message of an external server's answer is. why is the audit reason for vReverse.
func classify(raw []byte, id json.RawMessage) (v verdict, why string, isError bool) {
	var m struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
		Result  *struct {
			ResultType string `json:"resultType"`
			IsError    bool   `json:"isError"`
		} `json:"result"`
		Error *server.Error `json:"error"`
	}
	if json.Unmarshal(raw, &m) != nil || m.JSONRPC != "2.0" {
		return vBad, "", false
	}
	hasID := len(bytes.TrimSpace(m.ID)) > 0 && string(bytes.TrimSpace(m.ID)) != "null"
	if m.Method != "" {
		if hasID {
			return vReverse, reverseReason(m.Method), false
		}
		if m.Method == "notifications/progress" {
			return vProgress, "", false
		}
		return vDrop, "", false
	}
	if !hasID || !bytes.Equal(bytes.TrimSpace(m.ID), bytes.TrimSpace(id)) || (m.Result == nil && m.Error == nil) {
		return vBad, "", false
	}
	if m.Result != nil {
		switch m.Result.ResultType {
		case "input_required":
			// the 2026-07-28 form of a server asking the client for sampling, elicitation or roots
			return vReverse, "the server answered with a request for input from the client (input_required); a server of class external may not ask the client for anything", false
		case "task":
			return vReverse, "the server answered with a task, which the client did not ask for and the gateway does not route for a server of class external", false
		}
	}
	return vFinal, "", m.Error == nil && m.Result.IsError
}

// progressMessage rebuilds a progress notification from its numbers alone: the progress, the total, and the token the
// client sent. The server's message text, which is free text from an untrusted party, is left out. ok is false if
// the notification is not for this call's token or has no numeric progress.
func progressMessage(raw []byte, token json.RawMessage) ([]byte, bool) {
	if len(token) == 0 {
		return nil, false
	}
	var m struct {
		Params struct {
			Token    json.RawMessage `json:"progressToken"`
			Progress json.Number     `json:"progress"`
			Total    *json.Number    `json:"total"`
		} `json:"params"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if dec.Decode(&m) != nil || !bytes.Equal(bytes.TrimSpace(m.Params.Token), bytes.TrimSpace(token)) {
		return nil, false
	}
	if _, err := m.Params.Progress.Float64(); err != nil {
		return nil, false
	}
	params := map[string]any{"progressToken": token, "progress": m.Params.Progress}
	if m.Params.Total != nil {
		if _, err := m.Params.Total.Float64(); err == nil {
			params["total"] = *m.Params.Total
		}
	}
	b, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": "notifications/progress", "params": params})
	return b, err == nil
}

// relayExternal passes on the answer of a target of class external: one JSON message, or an event stream, read with
// the limits of ADR-0001 D51 d and judged message by message (c). It returns the outcome of the call and sets
// the reason of the audit record when the gateway ended the call.
//
// Memory: the whole of a plain answer is held, up to ExternalMaxResult bytes; of a stream only one event at a time,
// up to the same number, and nothing past ExternalMaxStream bytes is read at all, comments and keep-alive lines
// included. So an upstream that never stops costs the gateway the one buffer and the call's time limit.
func (g *Gateway) relayExternal(w http.ResponseWriter, req *server.Request, resp *http.Response, rec *callRecord, token json.RawMessage) string {
	end := func(started bool, outcome, why string) string {
		rec.reason(why)
		text := "The call was ended by the gateway: " + why + "."
		if outcome == invocation.OutcomeResultTooLarge {
			text += " Ask for less, or for a narrower part of it."
		}
		g.writeFinal(w, req.ID, started, text)
		return outcome
	}
	maxResult, maxStream := g.cfg.ExternalMaxResult, g.cfg.ExternalMaxStream
	switch transport.MediaType(resp.Header.Get("Content-Type")) {
	case "application/json":
		raw, err := transport.ReadBounded(resp.Body, maxResult)
		if errors.Is(err, transport.ErrTooLarge) {
			return end(false, invocation.OutcomeResultTooLarge, fmt.Sprintf("the server's answer is longer than the limit of %d bytes", maxResult))
		}
		if err != nil {
			g.upstreamError(w, req.ID, http.StatusBadGateway, "Upstream answer unusable; the outcome is unknown", invocation.OutcomeUnknown)
			return invocation.OutcomeUnknown
		}
		v, why, isError := classify(raw, req.ID)
		switch v {
		case vReverse:
			return end(false, invocation.OutcomeReverseRefused, why)
		case vFinal:
		default:
			g.upstreamError(w, req.ID, http.StatusBadGateway, "Upstream answer unusable; the outcome is unknown", invocation.OutcomeUnknown)
			return invocation.OutcomeUnknown
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(raw)
		var res struct {
			Error *server.Error `json:"error"`
		}
		_ = json.Unmarshal(raw, &res)
		switch {
		case res.Error != nil:
			return invocation.OutcomeRPCError
		case isError:
			return invocation.OutcomeToolError
		}
		return invocation.OutcomeOK
	case "text/event-stream":
	default:
		g.upstreamError(w, req.ID, http.StatusBadGateway, "Upstream answer unusable; the outcome is unknown", invocation.OutcomeUnknown)
		return invocation.OutcomeUnknown
	}

	started := false
	rc := http.NewResponseController(w)
	emit := func(msg []byte) bool {
		if !started {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(resp.StatusCode)
			rec.started()
			started = true
		}
		n, err := fmt.Fprintf(w, "event: message\ndata: %s\n\n", msg)
		rec.relayed(n)
		_ = rc.Flush()
		return err == nil
	}
	rd := bufio.NewReaderSize(resp.Body, 16<<10)
	var total int64
	var data []byte
	for {
		// one line, held up to the size of one event
		var line []byte
		for {
			chunk, more, err := rd.ReadLine()
			total += int64(len(chunk)) + 1
			if total > maxStream {
				return end(started, invocation.OutcomeResultTooLarge, fmt.Sprintf("the server's stream is longer than the limit of %d bytes", maxStream))
			}
			if int64(len(line)+len(chunk)) > maxResult {
				return end(started, invocation.OutcomeResultTooLarge, fmt.Sprintf("an event of the server's stream is longer than the limit of %d bytes", maxResult))
			}
			line = append(line, chunk...)
			if err != nil { // the stream ended (or the call's time ran out) before the answer
				if started {
					return end(true, invocation.OutcomeUnknown, "the server's stream ended without an answer")
				}
				g.upstreamError(w, req.ID, http.StatusBadGateway, "Upstream answer unusable; the outcome is unknown", invocation.OutcomeUnknown)
				return invocation.OutcomeUnknown
			}
			if !more {
				break
			}
		}
		switch {
		case bytes.HasPrefix(line, []byte("data:")):
			part := bytes.TrimPrefix(bytes.TrimPrefix(line, []byte("data:")), []byte(" "))
			if int64(len(data)+len(part)+1) > maxResult {
				return end(started, invocation.OutcomeResultTooLarge, fmt.Sprintf("an event of the server's stream is longer than the limit of %d bytes", maxResult))
			}
			if len(data) > 0 {
				data = append(data, '\n')
			}
			data = append(data, part...)
		case len(line) == 0 && len(data) > 0:
			var compact bytes.Buffer
			ok := json.Compact(&compact, data) == nil
			data = data[:0]
			if !ok {
				continue
			}
			msg := compact.Bytes()
			v, why, isError := classify(msg, req.ID)
			switch v {
			case vReverse:
				return end(started, invocation.OutcomeReverseRefused, why)
			case vProgress:
				if out, ok := progressMessage(msg, token); ok && !emit(out) {
					return invocation.OutcomeUnknown
				}
			case vFinal:
				if !emit(msg) {
					return invocation.OutcomeUnknown
				}
				var res struct {
					Error *server.Error `json:"error"`
				}
				_ = json.Unmarshal(msg, &res)
				switch {
				case res.Error != nil:
					return invocation.OutcomeRPCError
				case isError:
					return invocation.OutcomeToolError
				}
				return invocation.OutcomeStreamed
			}
		}
	}
}

// writeFinal ends a call with a tool error: as the whole answer if nothing was sent yet, else as the last event of
// the stream that was.
func (g *Gateway) writeFinal(w http.ResponseWriter, id json.RawMessage, started bool, text string) {
	res := g.toolErrorResult(id, text)
	if !started {
		transport.WriteJSON(w, http.StatusOK, res)
		return
	}
	b, _ := json.Marshal(res)
	_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", b)
	_ = http.NewResponseController(w).Flush()
}
