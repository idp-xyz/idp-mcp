package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"idp-mcp/internal/observability"
)

func TestTheGatewayDoesNotStartWithoutTheClientsFile(t *testing.T) {
	t.Setenv("IDP_GATEWAY_ID", "g1")
	t.Setenv("IDP_RELEASE_FILE", filepath.Join(t.TempDir(), "release.json"))
	t.Setenv("IDP_GATEWAY_CLIENTS_FILE", "")
	err := run(observability.NewLogger(os.Stderr, "error"))
	if err == nil {
		t.Fatal("the gateway started")
	}
	for _, want := range []string{"IDP_GATEWAY_CLIENTS_FILE", `"*": platform`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the message does not say %q: %v", want, err)
		}
	}
}

func TestTheGatewayDoesNotStartWithAnInvalidClientsFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "clients.yaml")
	if err := os.WriteFile(f, []byte("clients: {idp-host: {kind: friend}}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("IDP_GATEWAY_ID", "g1")
	t.Setenv("IDP_RELEASE_FILE", filepath.Join(t.TempDir(), "release.json"))
	t.Setenv("IDP_GATEWAY_CLIENTS_FILE", f)
	if err := run(observability.NewLogger(os.Stderr, "error")); err == nil || !strings.Contains(err.Error(), f) || !strings.Contains(err.Error(), "kind must be") {
		t.Fatalf("%v", err)
	}
}

func TestTheClientsFileIsReadBeforeAnythingIsStarted(t *testing.T) {
	// a valid file moves on to the next requirement, the release: which is how the test knows it was accepted
	f := filepath.Join(t.TempDir(), "clients.yaml")
	if err := os.WriteFile(f, []byte(`clients: {"*": platform}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("IDP_GATEWAY_ID", "g1")
	t.Setenv("IDP_RELEASE_FILE", filepath.Join(t.TempDir(), "absent.json"))
	t.Setenv("IDP_GATEWAY_CLIENTS_FILE", f)
	t.Setenv("IDP_GATEWAY_LISTEN", "127.0.0.1:0")
	err := run(observability.NewLogger(os.Stderr, "error"))
	if err == nil || strings.Contains(err.Error(), "CLIENTS") || !strings.Contains(err.Error(), "absent.json") {
		t.Fatalf("%v", err)
	}
}
