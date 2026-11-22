package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"idp-mcp/adapters/identity"
	"idp-mcp/internal/admission"
	"idp-mcp/internal/authorization"
	"idp-mcp/internal/client"
	"idp-mcp/internal/federation"
	"idp-mcp/internal/invocation"
	"idp-mcp/internal/observability"
	"idp-mcp/internal/policy"
	"idp-mcp/internal/release"
	"idp-mcp/internal/server"
	"idp-mcp/internal/transport"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// MaxUpstreamJSON bounds a buffered (non-streamed) tools/call response.
const MaxUpstreamJSON = 16 << 20

// MaxObservedStream bounds the copy of a relayed event stream kept to inspect its final message.
const MaxObservedStream = 1 << 20

func liveDigest(toolRaws, promptRaws, resRaws, tplRaws []json.RawMessage) (string, error) {
	tools, err := federation.NormalizeTools(toolRaws)
	if err != nil {
		return "", err
	}
	prompts, err := federation.NormalizePrompts(promptRaws)
	if err != nil {
		return "", err
	}
	resources, err := federation.NormalizeResources(resRaws)
	if err != nil {
		return "", err
	}
	templates, err := federation.NormalizeResourceTemplates(tplRaws)
	if err != nil {
		return "", err
	}
	return release.Catalog{Tools: tools, Prompts: prompts, Resources: resources, ResourceTemplates: templates}.Digest()
}

// Handler returns the gateway's HTTP handler.
func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /mcp", g.clientFacing(g.handleMCP))
	mux.HandleFunc("/mcp", g.clientFacing(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", "POST")
		transport.WriteError(w, http.StatusMethodNotAllowed, nil, &server.Error{Code: server.CodeInvalidRequest, Message: "Only POST /mcp is supported in modern mode"})
	}))
	for _, p := range []string{"GET /.well-known/oauth-protected-resource", "GET /.well-known/oauth-protected-resource/mcp"} {
		mux.HandleFunc(p, g.clientFacing(g.handleMetadata))
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		transport.WriteJSON(w, http.StatusOK, map[string]string{"status": "live"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if g.cur.Load() == nil {
			transport.WriteJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "no release"})
			return
		}
		transport.WriteJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		transport.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
	})
	return observability.HTTPMetrics(g.metrics, "idp_mcp_gateway", mux)
}

// clientFacing applies DNS-rebinding defenses: a single Host that names an accepted host, and an
// Origin, if any, that equals it.
func (g *Gateway) clientFacing(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(r.Header.Values("Origin")) > 1 {
			transport.WriteError(w, http.StatusForbidden, nil, &server.Error{Code: server.CodeInvalidRequest, Message: "Forbidden: duplicate Origin"})
			return
		}
		host := strings.ToLower(r.Host)
		name := host
		if h, _, err := net.SplitHostPort(host); err == nil {
			name = h
		}
		name = strings.Trim(name, "[]")
		if !g.acceptsHost(name) {
			transport.WriteError(w, http.StatusForbidden, nil, &server.Error{Code: server.CodeInvalidRequest, Message: "Forbidden: Host not allowed"})
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || strings.ToLower(u.Host) != host || (u.Path != "" && u.Path != "/") || u.User != nil {
				transport.WriteError(w, http.StatusForbidden, nil, &server.Error{Code: server.CodeInvalidRequest, Message: "Forbidden: Origin not allowed"})
				return
			}
		}
		next(w, r)
	}
}

func (g *Gateway) acceptsHost(name string) bool {
	if g.hosts[name] {
		return true
	}
	if st := g.cur.Load(); st != nil && st.doc.Auth.JWT != nil {
		if u, err := url.Parse(st.doc.Auth.JWT.Resource); err == nil && strings.EqualFold(u.Hostname(), name) {
			return true
		}
	}
	return false
}

func (g *Gateway) handleMetadata(w http.ResponseWriter, _ *http.Request) {
	st := g.cur.Load()
	if st == nil || st.auth.ResourceMetadata() == nil {
		transport.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	}
	transport.WriteJSON(w, http.StatusOK, st.auth.ResourceMetadata())
}

func (g *Gateway) handleMCP(w http.ResponseWriter, r *http.Request) {
	if transport.MediaType(r.Header.Get("Content-Type")) != "application/json" {
		transport.WriteError(w, http.StatusUnsupportedMediaType, nil, &server.Error{Code: server.CodeInvalidRequest, Message: "Content-Type must be application/json"})
		return
	}
	body, err := transport.ReadBounded(r.Body, server.MaxRequestBody)
	if err != nil {
		transport.WriteError(w, http.StatusRequestEntityTooLarge, nil, &server.Error{Code: server.CodeInvalidRequest, Message: "Request body too large"})
		return
	}
	req, rej := server.Admit(body, r.Header.Get(server.HeaderProtocolVersion), r.Header.Get(server.HeaderMethod))
	if rej != nil {
		transport.WriteRejection(w, rej)
		return
	}
	// Mcp-Param-* headers are forwarded to the upstream (forward); refuse the ones past the bounds early
	if _, rej := server.ParamHeaders(r.Header, req.ID); rej != nil {
		transport.WriteRejection(w, rej)
		return
	}
	// one server span per request; a valid incoming traceparent is continued, else a trace starts
	ctx := observability.Propagator.Extract(r.Context(), propagation.HeaderCarrier(r.Header))
	ctx, span := g.tracer.Start(ctx, "mcp "+req.Method, trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(attribute.String("mcp.method", req.Method)))
	defer span.End()
	r = r.WithContext(ctx)
	st := g.cur.Load()
	if st == nil {
		transport.WriteError(w, http.StatusServiceUnavailable, req.ID, &server.Error{Code: server.CodeInternalError, Message: "Gateway has no active release"})
		return
	}
	pr, ok := g.authenticate(w, r, st, req)
	if !ok {
		return
	}
	r = r.WithContext(withPrincipal(r.Context(), pr))
	if req.IsNotification() {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if !g.withinLimits(w, st, req, pr) {
		return
	}
	switch req.Method {
	case "server/discover":
		caps := federatedCapabilities(st.doc)
		if !st.policy.Listed(pr) { // what the server offers is not told to a client it does not serve
			caps = map[string]any{"tools": map[string]any{"listChanged": true}}
		}
		transport.WriteResult(w, req.ID, server.DiscoverResultWith(g.cfg.Info, caps))
	case "tools/list":
		rec := g.recorder(r, st, pr, req, invocation.Whole)
		var tools []server.Tool
		for _, pair := range st.policy.VisibleTools(pr) {
			if rt, ok := st.router.Route(pair[0], pair[1]); ok {
				tools = append(tools, rt.Listed())
			}
		}
		rec.doneList(st, pr)
		transport.WriteResult(w, req.ID, server.ToolsListResult(tools, g.cfg.Info))
	case "tools/call":
		g.toolsCall(w, r, st, req, pr)
	case "prompts/list":
		g.promptsList(w, r, st, req, pr)
	case "prompts/get":
		g.promptsGet(w, r, st, req, pr)
	case "resources/list":
		g.resourcesList(w, r, st, req, pr, false)
	case "resources/templates/list":
		g.resourcesList(w, r, st, req, pr, true)
	case "resources/read":
		g.resourcesRead(w, r, st, req, pr)
	case "completion/complete":
		g.complete(w, r, st, req, pr)
	case "subscriptions/listen":
		g.listen(w, r, st, req, pr)
	case "tasks/get", "tasks/cancel", "tasks/update":
		g.taskRequest(w, r, st, req, pr)
	default:
		transport.WriteError(w, http.StatusNotFound, req.ID, server.MethodNotFound(req.Method))
	}
}

// authenticate admits the bearer credential or answers 401. A refused credential is audited with the gateway's
// own words for the cause and nothing of the credential; a source that fails over and over is audited only up
// to authFailureRecords a minute (the rest are counted in the metrics), so that the audit cannot be flooded
// by someone with no credential at all.
func (g *Gateway) authenticate(w http.ResponseWriter, r *http.Request, st *state, req *server.Request) (authorization.Principal, bool) {
	tok, err := identity.Bearer(r)
	var pr authorization.Principal
	if err == nil {
		pr, err = st.auth.Authenticate(r.Context(), tok)
	}
	if err != nil {
		g.authFailures.Inc()
		host, _, splitErr := net.SplitHostPort(r.RemoteAddr)
		if splitErr != nil {
			host = r.RemoteAddr
		}
		if g.limiter.Allow("authfail\x00"+host, admission.Limit{Requests: authFailureRecords, Window: time.Minute}) == 0 {
			reason := "the credential was refused"
			if errors.Is(err, identity.ErrNoCredentials) {
				reason = "no bearer credential"
			}
			now := time.Now()
			g.cfg.Recorder.Record(invocation.Record{At: now.UTC(), ReleaseDigest: st.env.Digest, Subject: invocation.NoSubject, AuthMethod: st.doc.Auth.Mode,
				Method: req.Method, Tool: invocation.Whole, Decision: invocation.Deny, Outcome: invocation.OutcomeUnauthorized, Reason: reason,
				TraceID: observability.TraceID(r.Context())})
		}
		w.Header().Set("WWW-Authenticate", st.auth.Challenge(!errors.Is(err, identity.ErrNoCredentials)))
		transport.WriteError(w, http.StatusUnauthorized, req.ID, &server.Error{Code: server.CodeInvalidRequest, Message: "Unauthorized"})
		return pr, false
	}
	return pr, true
}

// authFailureRecords is how many refused credentials of one source address are written to the audit each minute.
const authFailureRecords = 30

// withinLimits applies the request limits of the caller's client and of the caller's subject (ADR-0001 D49) and
// answers 429 with Retry-After, and a record, when either is exhausted. Every authenticated request counts,
// refused ones too, so that probing for what is allowed is limited like using it.
func (g *Gateway) withinLimits(w http.ResponseWriter, st *state, req *server.Request, pr authorization.Principal) bool {
	client := pr.ClientID()
	var wait time.Duration
	which := "client"
	if lim, limited := g.cfg.Clients.ClientLimit(client); limited {
		wait = g.limiter.Allow("client\x00"+client, lim)
	}
	if lim, limited := g.cfg.Clients.SubjectLimit(client); wait == 0 && limited {
		wait = g.limiter.Allow("subject\x00"+pr.Tenant+"\x00"+pr.Subject, lim)
		which = "subject"
	}
	if wait == 0 {
		return true
	}
	secs := int((wait + time.Second - 1) / time.Second)
	g.cfg.Recorder.Record(invocation.Record{At: time.Now().UTC(), ReleaseDigest: st.env.Digest, Subject: pr.Subject, Client: pr.Client, Actor: pr.Actor,
		AuthMethod: pr.Method, Method: req.Method, Tool: invocation.Whole, Decision: invocation.Deny, Outcome: invocation.OutcomeRateLimited,
		Reason: fmt.Sprintf("%s rate limit; retry after %ds", which, secs)})
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	transport.WriteError(w, http.StatusTooManyRequests, req.ID, &server.Error{Code: server.CodeRateLimited,
		Message: fmt.Sprintf("Rate limit exceeded for this %s: retry after %d seconds", which, secs), Data: map[string]any{"retryAfterSeconds": secs}})
	return false
}

type callParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func (g *Gateway) toolsCall(w http.ResponseWriter, r *http.Request, st *state, req *server.Request, pr authorization.Principal) {
	if rej := req.CheckNameHeader(r.Header.Get(server.HeaderName)); rej != nil {
		transport.WriteRejection(w, rej)
		return
	}
	var p callParams
	if err := req.DecodeParams(&p); err != nil {
		transport.WriteError(w, http.StatusBadRequest, req.ID, err.(*server.Error))
		return
	}
	trace.SpanFromContext(r.Context()).SetAttributes(attribute.String("mcp.tool", p.Name))
	rec := g.recorder(r, st, pr, req, p.Name)
	if len(p.Arguments) > 0 {
		rec.rec.ArgsDigest, _ = release.Digest(p.Arguments)
	}
	rt, found := st.router.Lookup(p.Name)
	var dec authorization.Decision
	if found {
		dec = st.policy.Decide(pr, rt.Target, rt.Tool.Name)
	}
	if !found || !dec.Allowed {
		if !found {
			rec.reason(g.refusal(st, pr, ""))
		}
		rec.reason(dec.Why)
		rec.done("", invocation.Deny, invocation.OutcomeDenied)
		transport.WriteError(w, http.StatusOK, req.ID, server.UnknownTool(p.Name))
		return
	}
	if dec.Exception != "" {
		rec.reason("host-only exception: " + dec.Exception)
	}
	if g.refuseBlocked(w, st, req, rec, rt.Target, "Tool") {
		return
	}
	if err := st.args.Validate(p.Name, p.Arguments); err != nil {
		rec.done(rt.Target, invocation.Deny, invocation.OutcomeInvalidArgs)
		if st.isExternal(rt.Target) {
			// a tool error, not a protocol error: the model reads it and can correct its arguments (ADR-0001 D51 e)
			rec.reason("the arguments do not match the pinned input schema")
			transport.WriteJSON(w, http.StatusOK, g.toolErrorResult(req.ID, "Invalid arguments for tool "+p.Name+": "+err.Error()+". The call was not sent; correct the arguments and call again."))
			return
		}
		transport.WriteError(w, http.StatusOK, req.ID, &server.Error{Code: server.CodeInvalidParams, Message: "Invalid arguments for tool " + p.Name,
			Data: map[string]string{"reason": err.Error()}})
		return
	}
	params := rawParams(req)
	params["name"], _ = json.Marshal(rt.Tool.Name)
	var observe func(json.RawMessage)
	if targetHas(st.doc, rt.Target, release.CapTasks) {
		observe = func(msg json.RawMessage) { g.tasks.bindFromResult(msg, rt.Target, p.Name, pr) }
	}
	rec.done(rt.Target, invocation.Allow, g.forward(w, r, st, req, rt.Endpoint, rt.Tool.Name, params, rec.to(rt.Target), observe))
}

// refuseBlocked answers, and records, a request to a target whose calls are blocked (drift; for an external target
// also an unverified or unreachable catalog, ADR-0001 D51 f). kind is "Tool", "Prompt" or "Resource". The audit
// reason is set for external targets only, so that the record of an internal target is what it was.
func (g *Gateway) refuseBlocked(w http.ResponseWriter, st *state, req *server.Request, rec *callRecord, target, kind string) bool {
	why := g.blocked(st, target)
	if why == "" {
		return false
	}
	if st.isExternal(target) {
		rec.reason(why)
	}
	rec.done(target, invocation.Allow, invocation.OutcomeNotDelivered)
	transport.WriteError(w, http.StatusServiceUnavailable, req.ID, &server.Error{Code: server.CodeInternalError,
		Message: kind + " temporarily unavailable: " + why})
	return true
}

// forward sends the request to the upstream with the given (possibly rewritten) params and relays
// the answer: JSON is buffered and checked, an event stream is passed through as it arrives. The
// client's params - _meta, inputResponses, requestState, progress tokens - are forwarded as they
// are, so multi-round flows (InputRequiredResult) work end to end. observe, if given, sees the
// final JSON-RPC message (the JSON body, or the last message of a stream that fit in memory).
func (g *Gateway) forward(w http.ResponseWriter, r *http.Request, st *state, req *server.Request, endpoint, nameHeader string,
	params map[string]json.RawMessage, rec *callRecord, observe ...func(json.RawMessage)) (outcome string) {
	var seen func(json.RawMessage)
	if len(observe) > 0 {
		seen = observe[0]
	}
	// the caller key is the gateway's: a client's own is removed; a target approved for identity gets the verified one
	caller, known := principalFrom(r.Context())
	tgt := targetByEndpoint(st.doc, endpoint)
	external := tgt != nil && tgt.External()
	var progress json.RawMessage
	var err error
	// a target of class external at a bridge address is ours: the bridge must know whose token to use (D51 a, revised)
	bridge := external && g.cfg.Bridges.Matches(endpoint)
	if external {
		// a target of class external is sent no identity whatever its identity mode says, and a _meta made of the
		// allow-list alone (ADR-0001 D51 a, b); stampCaller is not even called. At a bridge address the one addition
		// is the signed assertion, made over the params as they are sent
		params, progress = externalParams(params)
		if bridge {
			params, err = assertCaller(params, caller, known, g.cfg.CallerSigner, endpoint, req.Method)
		}
	} else {
		params, err = stampCaller(params, identityOf(st.doc, endpoint), caller, known, g.cfg.CallerSigner, endpoint, req.Method)
	}
	if err != nil { // the signing key failed: send nothing rather than an identity the upstream cannot check
		g.cfg.Log.Error("caller assertion", "err", err)
		g.upstreamError(w, req.ID, http.StatusBadGateway, "Upstream unavailable; the call was not delivered", invocation.OutcomeNotDelivered)
		return invocation.OutcomeNotDelivered
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": req.ID, "method": req.Method, "params": params})
	ctx, cancel := context.WithTimeout(r.Context(), g.cfg.CallTimeout)
	defer cancel()
	// a client span for the upstream call; the span's context (new span id) travels in traceparent
	ctx, span := g.tracer.Start(ctx, "upstream "+req.Method, trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attribute.String("mcp.method", req.Method), attribute.String("server.address", client.Redact(endpoint))))
	defer func() {
		span.SetAttributes(attribute.String("idp.outcome", outcome))
		if outcome == invocation.OutcomeUnknown || outcome == invocation.OutcomeNotDelivered {
			span.SetStatus(codes.Error, outcome)
		}
		span.End()
	}()
	up, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	up.Header = client.Headers(req.Method, nameHeader)
	// the one client header family that passes through: an intermediary forwards the Mcp-Param-* headers it
	// does not recognise (2026-07-28 transport, SEP-2243). Authorization, Cookie and the rest do not.
	extra, _ := server.ParamHeaders(r.Header, req.ID) // within the bounds: handleMCP checked them
	for k, vs := range extra {
		up.Header[k] = vs
	}
	if !external { // an external server is not told which trace the call belongs to
		observability.Propagator.Inject(ctx, propagation.HeaderCarrier(up.Header))
	}
	resp, err := st.upstream.HTTP.Do(up)
	if err != nil {
		var op *net.OpError
		if errors.Is(err, policy.ErrBlocked) || (errors.As(err, &op) && op.Op == "dial") {
			g.upstreamError(w, req.ID, http.StatusBadGateway, "Upstream unavailable; the call was not delivered", invocation.OutcomeNotDelivered)
			return invocation.OutcomeNotDelivered
		}
		g.upstreamError(w, req.ID, http.StatusGatewayTimeout, "Upstream did not answer; the outcome is unknown", invocation.OutcomeUnknown)
		return invocation.OutcomeUnknown
	}
	defer resp.Body.Close()
	if external {
		return g.relayExternal(w, req, resp, rec, progress, bridge)
	}
	switch transport.MediaType(resp.Header.Get("Content-Type")) {
	case "application/json":
		raw, err := transport.ReadBounded(resp.Body, MaxUpstreamJSON)
		if err != nil {
			g.upstreamError(w, req.ID, http.StatusBadGateway, "Upstream answer unusable; the outcome is unknown", invocation.OutcomeUnknown)
			return invocation.OutcomeUnknown
		}
		var msg struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Result  *struct {
				IsError bool `json:"isError"`
			} `json:"result"`
			Error *server.Error `json:"error"`
		}
		if json.Unmarshal(raw, &msg) != nil || msg.JSONRPC != "2.0" || !bytes.Equal(bytes.TrimSpace(msg.ID), bytes.TrimSpace(req.ID)) || (msg.Result == nil && msg.Error == nil) {
			g.upstreamError(w, req.ID, http.StatusBadGateway, "Upstream answer unusable; the outcome is unknown", invocation.OutcomeUnknown)
			return invocation.OutcomeUnknown
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(raw)
		if seen != nil {
			seen(raw)
		}
		switch {
		case msg.Error != nil:
			return invocation.OutcomeRPCError
		case msg.Result.IsError:
			return invocation.OutcomeToolError
		}
		return invocation.OutcomeOK
	case "text/event-stream":
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(resp.StatusCode)
		rec.started()
		rc := http.NewResponseController(w)
		buf := make([]byte, 32<<10)
		var tee []byte // bounded copy for observe
		overflow := false
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					return invocation.OutcomeUnknown
				}
				rec.relayed(n)
				_ = rc.Flush()
				if seen != nil && !overflow {
					if len(tee)+n > MaxObservedStream {
						overflow, tee = true, nil
					} else {
						tee = append(tee, buf[:n]...)
					}
				}
			}
			if err == io.EOF {
				if seen != nil && !overflow {
					if msgs := transport.SSEMessages(tee); len(msgs) > 0 {
						seen(msgs[len(msgs)-1])
					}
				}
				return invocation.OutcomeStreamed
			}
			if err != nil {
				return invocation.OutcomeUnknown
			}
		}
	default:
		g.upstreamError(w, req.ID, http.StatusBadGateway, "Upstream answer unusable; the outcome is unknown", invocation.OutcomeUnknown)
		return invocation.OutcomeUnknown
	}
}

func (g *Gateway) upstreamError(w http.ResponseWriter, id json.RawMessage, status int, msg, outcome string) {
	transport.WriteError(w, status, id, &server.Error{Code: server.CodeInternalError, Message: msg, Data: map[string]string{"outcome": outcome}})
}
