package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"idp-mcp/internal/invocation"
	"idp-mcp/internal/release"
	"idp-mcp/internal/transport"
)

// Internal registry API used by gateways (authenticated with the gateway's own credential):
//
//	GET  /internal/v1/gateway/desired      200 Envelope (ETag = digest) | 304 | 204 no desired release
//	POST /internal/v1/gateway/heartbeat    Status
//	POST /internal/v1/gateway/invocations  {"records": [...]}
const (
	PathDesired     = "/internal/v1/gateway/desired"
	PathHeartbeat   = "/internal/v1/gateway/heartbeat"
	PathInvocations = "/internal/v1/gateway/invocations"
)

// RegistrySync keeps a gateway on its desired release and reports back.
type RegistrySync struct {
	BaseURL           string
	Token             string
	HTTP              *http.Client
	Gateway           *Gateway
	CacheFile         string // last activated envelope, used to start when the registry is down
	PollInterval      time.Duration
	HeartbeatInterval time.Duration
	Log               *slog.Logger
}

func (s *RegistrySync) do(ctx context.Context, method, path string, body any, etag string) (*http.Response, error) {
	var rd *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(s.BaseURL, "/")+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if etag != "" {
		req.Header.Set("If-None-Match", `"`+etag+`"`)
	}
	return s.HTTP.Do(req)
}

// LoadCache activates the cached envelope, if there is one.
func (s *RegistrySync) LoadCache() {
	if s.CacheFile == "" {
		return
	}
	b, err := os.ReadFile(s.CacheFile)
	if err != nil {
		return
	}
	var env release.Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		s.Log.Warn("release cache unreadable; ignored", "err", err)
		return
	}
	if err := s.Gateway.Activate(&env); err != nil {
		s.Log.Warn("cached release refused", "err", err)
		return
	}
	s.Log.Info("started on cached release", "digest", env.Digest)
}

func (s *RegistrySync) saveCache(env *release.Envelope) {
	if s.CacheFile == "" {
		return
	}
	b, _ := json.Marshal(env)
	tmp := s.CacheFile + ".tmp"
	if err := os.MkdirAll(filepath.Dir(s.CacheFile), 0o700); err == nil {
		if err = os.WriteFile(tmp, b, 0o600); err == nil {
			err = os.Rename(tmp, s.CacheFile)
		}
		if err != nil {
			s.Log.Warn("release cache not written", "err", err)
		}
	}
}

// PollOnce fetches the desired release and activates it if it changed.
func (s *RegistrySync) PollOnce(ctx context.Context) error {
	resp, err := s.do(ctx, http.MethodGet, PathDesired, nil, s.Gateway.Status().Digest)
	if err != nil {
		return fmt.Errorf("registry unreachable: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified, http.StatusNoContent:
		return nil
	case http.StatusOK:
	default:
		return fmt.Errorf("desired release: HTTP %d", resp.StatusCode)
	}
	raw, err := transport.ReadBounded(resp.Body, 32<<20)
	if err != nil {
		return err
	}
	var env release.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("desired release is not an envelope: %w", err)
	}
	if env.Digest == s.Gateway.Status().Digest {
		return nil
	}
	if err := s.Gateway.Activate(&env); err != nil {
		return err
	}
	s.saveCache(&env)
	return nil
}

// Heartbeat reports the gateway's status.
func (s *RegistrySync) Heartbeat(ctx context.Context) error {
	resp, err := s.do(ctx, http.MethodPost, PathHeartbeat, s.Gateway.Status(), "")
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("heartbeat: HTTP %d", resp.StatusCode)
	}
	return nil
}

// Sink ships invocation batches to the registry.
func (s *RegistrySync) Sink() invocation.Sink {
	return func(ctx context.Context, batch []invocation.Record) error {
		resp, err := s.do(ctx, http.MethodPost, PathInvocations, map[string]any{"records": batch}, "")
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			return fmt.Errorf("invocations: HTTP %d", resp.StatusCode)
		}
		return nil
	}
}

// Run polls and heartbeats until ctx ends. Errors are logged and surfaced in Status.
func (s *RegistrySync) Run(ctx context.Context) {
	poll := time.NewTicker(s.PollInterval)
	beat := time.NewTicker(s.HeartbeatInterval)
	defer poll.Stop()
	defer beat.Stop()
	step := func() {
		c, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := s.PollOnce(c); err != nil {
			s.Gateway.RecordError(err)
			s.Log.Warn("desired release", "err", err)
		}
	}
	step()
	for {
		select {
		case <-ctx.Done():
			return
		case <-poll.C:
			step()
		case <-beat.C:
			c, cancel := context.WithTimeout(ctx, 5*time.Second)
			if err := s.Heartbeat(c); err != nil {
				s.Log.Warn("heartbeat", "err", err)
			}
			cancel()
		}
	}
}
