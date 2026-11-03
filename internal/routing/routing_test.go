package routing

import (
	"testing"

	"idp-mcp/internal/release"
	"idp-mcp/internal/server"
)

func TestRouterMapsExposedNamesBothWays(t *testing.T) {
	r := New(&release.Document{ToolNaming: release.NamingPrefixed, Targets: []release.Target{
		{Name: "a", Endpoint: "http://a/mcp", Tools: []server.Tool{{Name: "echo", Description: "pinned"}}},
		{Name: "b", Endpoint: "http://b/mcp", Tools: []server.Tool{{Name: "x__y"}}},
	}})
	rt, ok := r.Lookup("a__echo")
	if !ok || rt.Target != "a" || rt.Tool.Name != "echo" || rt.Endpoint != "http://a/mcp" {
		t.Fatalf("%+v", rt)
	}
	if l := rt.Listed(); l.Name != "a__echo" || l.Description != "pinned" || rt.Tool.Name != "echo" {
		t.Fatalf("listed %+v / route tool %+v", l, rt.Tool)
	}
	if rt, ok := r.Lookup("b__x__y"); !ok || rt.Tool.Name != "x__y" {
		t.Fatalf("%+v", rt)
	}
	if _, ok := r.Lookup("a__nope"); ok {
		t.Fatal("unknown tool routed")
	}
	if _, ok := r.Route("b", "x__y"); !ok || r.Endpoint("b") != "http://b/mcp" {
		t.Fatal("route by target/tool")
	}
}

func TestNativeNamingAndPinnedPrompts(t *testing.T) {
	r := New(&release.Document{ToolNaming: release.NamingNative, Targets: []release.Target{
		{Name: "a", Endpoint: "http://a/mcp", Tools: []server.Tool{{Name: "echo"}}, Prompts: []server.Prompt{{Name: "greet", Description: "pinned"}}},
		{Name: "b", Endpoint: "http://b/mcp", Tools: []server.Tool{{Name: "sum"}}},
	}})
	if rt, ok := r.Lookup("sum"); !ok || rt.Target != "b" || rt.Listed().Name != "sum" {
		t.Fatalf("%+v", rt)
	}
	if pr, ok := r.LookupPrompt("greet"); !ok || pr.Target != "a" || pr.Listed().Description != "pinned" {
		t.Fatalf("%+v", pr)
	}
	if _, ok := r.LookupPrompt("other"); ok {
		t.Fatal("unpinned prompt resolved")
	}
	p := New(&release.Document{ToolNaming: release.NamingPrefixed, Targets: []release.Target{{Name: "a", Endpoint: "http://a/mcp",
		Prompts: []server.Prompt{{Name: "greet"}}}}})
	if pr, ok := p.LookupPrompt("a__greet"); !ok || pr.Prompt.Name != "greet" || pr.Listed().Name != "a__greet" {
		t.Fatalf("%+v", pr)
	}
	if _, ok := p.LookupPrompt("greet"); ok {
		t.Fatal("prefixed mode resolved an unprefixed name")
	}
}
