package authorization

import (
	"testing"

	"idp-mcp/internal/admission"
	"idp-mcp/internal/release"
)

func policy() *Policy {
	return Compile(&release.Document{TenantID: "t1", Grants: []release.Grant{
		{Target: "minimal", Tools: []string{"echo", "sum"}, Roles: []string{"operator"}},
		{Target: "minimal", Tools: []string{"sum"}, Roles: []string{"viewer"}},
		{Target: "reference", Tools: []string{"test_simple_text"}, Roles: []string{"operator"}},
	}}, admission.Unrestricted())
}

func TestAllowedNeedsTenantSubjectAndRole(t *testing.T) {
	p := policy()
	op := Principal{Subject: "a", Tenant: "t1", Roles: []string{"operator"}}
	viewer := Principal{Subject: "b", Tenant: "t1", Roles: []string{"viewer"}}
	foreign := Principal{Subject: "c", Tenant: "t2", Roles: []string{"operator"}}
	cases := []struct {
		p            Principal
		target, tool string
		want         bool
	}{
		{op, "minimal", "echo", true},
		{op, "reference", "test_simple_text", true},
		{viewer, "minimal", "sum", true},
		{viewer, "minimal", "echo", false},
		{foreign, "minimal", "echo", false},
		{Principal{Tenant: "t1", Roles: []string{"operator"}}, "minimal", "echo", false},
		{op, "minimal", "rm", false},
		{op, "other", "echo", false},
	}
	for _, c := range cases {
		if got := p.Allowed(c.p, c.target, c.tool); got != c.want {
			t.Errorf("%+v %s/%s = %v", c.p, c.target, c.tool, got)
		}
	}
}

func TestVisibleToolsAreSortedAndFiltered(t *testing.T) {
	got := policy().VisibleTools(Principal{Subject: "a", Tenant: "t1", Roles: []string{"operator"}})
	want := [][2]string{{"minimal", "echo"}, {"minimal", "sum"}, {"reference", "test_simple_text"}}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%v", got)
		}
	}
	if v := policy().VisibleTools(Principal{Subject: "c", Tenant: "t2", Roles: []string{"operator"}}); len(v) != 0 {
		t.Fatalf("foreign tenant sees %v", v)
	}
}

func TestPromptAndResourceGrants(t *testing.T) {
	p := Compile(&release.Document{TenantID: "t1", Grants: []release.Grant{
		{Target: "ref", Prompts: []string{"greet"}, Roles: []string{"viewer"}},
		{Target: "ref", Prompts: []string{"*"}, Resources: true, Roles: []string{"operator"}},
	}}, admission.Unrestricted())
	op := Principal{Subject: "a", Tenant: "t1", Roles: []string{"operator"}}
	viewer := Principal{Subject: "b", Tenant: "t1", Roles: []string{"viewer"}}
	foreign := Principal{Subject: "c", Tenant: "t2", Roles: []string{"operator"}}
	if !p.AllowedPrompt(op, "ref", "anything") || !p.AllowedPrompt(viewer, "ref", "greet") || p.AllowedPrompt(viewer, "ref", "other") {
		t.Fatal("prompt grants")
	}
	if p.AllowedPrompt(foreign, "ref", "greet") || p.AllowedResources(foreign, "ref") || len(p.PromptTargets(foreign)) != 0 {
		t.Fatal("foreign tenant allowed")
	}
	if !p.AllowedResources(op, "ref") || p.AllowedResources(viewer, "ref") {
		t.Fatal("resource grants")
	}
	if got := p.PromptTargets(viewer); len(got) != 1 || got[0] != "ref" {
		t.Fatal(got)
	}
	if got := p.ResourceTargets(viewer); len(got) != 0 {
		t.Fatal(got)
	}
}

func clientsPolicy(t *testing.T, clients string) *Policy {
	t.Helper()
	c, err := admission.Parse([]byte(clients))
	if err != nil {
		t.Fatal(err)
	}
	return Compile(&release.Document{TenantID: "t1", ToolNaming: release.NamingPrefixed, Grants: []release.Grant{
		{Target: "minimal", Tools: []string{"echo", "sum"}, Roles: []string{"operator"}},
		{Target: "ref", Prompts: []string{"*"}, Resources: true, Roles: []string{"operator"}},
	}}, c)
}

func TestAToolNeedsTheRoleAndTheClient(t *testing.T) {
	p := clientsPolicy(t, `clients:
  idp-host: {kind: platform, host: true}
  partner: {kind: external, tools: ["minimal__sum"]}
hostOnlyTools: ["minimal__echo"]
`)
	as := func(client string) Principal {
		return Principal{Subject: "a", Tenant: "t1", Roles: []string{"operator"}, Method: "jwt", Client: client}
	}
	cases := []struct {
		client, tool string
		want         bool
	}{
		{"idp-host", "echo", true}, {"idp-host", "sum", true},
		{"partner", "sum", true}, {"partner", "echo", false},
		{"stranger", "sum", false}, {"", "sum", false},
	}
	for _, c := range cases {
		if got := p.Allowed(as(c.client), "minimal", c.tool); got != c.want {
			t.Errorf("client %q tool %s: %v", c.client, c.tool, got)
		}
	}
	if got := p.VisibleTools(as("partner")); len(got) != 1 || got[0] != [2]string{"minimal", "sum"} {
		t.Errorf("partner sees %v", got)
	}
	if got := p.VisibleTools(as("stranger")); len(got) != 0 {
		t.Errorf("stranger sees %v", got)
	}
	// the right client does not make up for the wrong role
	viewer := Principal{Subject: "b", Tenant: "t1", Roles: []string{"viewer"}, Method: "jwt", Client: "idp-host"}
	if p.Allowed(viewer, "minimal", "echo") {
		t.Error("the host client granted a tool the role does not")
	}
	if d := p.Decide(viewer, "minimal", "echo"); d.Why != WhyRole {
		t.Errorf("%+v", d)
	}
}

func TestAPrincipalWithAnAPIKeyIsTheClientNamedAfterTheKey(t *testing.T) {
	p := clientsPolicy(t, `clients: {"api-key:k1": platform}`)
	key := func(id string) Principal {
		return Principal{Subject: "a", Tenant: "t1", Roles: []string{"operator"}, Method: "api-key", KeyID: id}
	}
	if !p.Allowed(key("k1"), "minimal", "echo") || p.Allowed(key("k2"), "minimal", "echo") {
		t.Fatal("API keys are not clients of their own")
	}
}

func TestPromptsAndResourcesFollowTheClientToo(t *testing.T) {
	p := clientsPolicy(t, `clients:
  partner: {kind: external, servers: [ref]}
  toolsonly: {kind: external, tools: ["ref__t"]}
  plain: platform
`)
	as := func(client string) Principal {
		return Principal{Subject: "a", Tenant: "t1", Roles: []string{"operator"}, Method: "jwt", Client: client}
	}
	for client, want := range map[string]bool{"partner": true, "plain": true, "toolsonly": false, "stranger": false} {
		if got := p.AllowedPrompt(as(client), "ref", "greet"); got != want {
			t.Errorf("prompt for %s: %v", client, got)
		}
		if got := p.AllowedResources(as(client), "ref"); got != want {
			t.Errorf("resources for %s: %v", client, got)
		}
		if got := len(p.PromptTargets(as(client))) == 1; got != want {
			t.Errorf("prompt targets for %s: %v", client, got)
		}
		if got := len(p.ResourceTargets(as(client))) == 1; got != want {
			t.Errorf("resource targets for %s: %v", client, got)
		}
	}
	if p.AllowedPrompt(as("partner"), "other", "greet") {
		t.Error("an external client reached a server it does not list")
	}
}

func TestEverythingOfAnExternalTargetIsHostOnlyBecauseOfItsClassAndNothingElseIs(t *testing.T) {
	c, err := admission.Parse([]byte(`clients:
  idp-host: {kind: platform, host: true}
  plain: platform
`))
	if err != nil {
		t.Fatal(err)
	}
	doc := &release.Document{TenantID: "t1", ToolNaming: release.NamingPrefixed,
		Targets: []release.Target{{Name: "minimal", Class: release.ClassExternal}, {Name: "ref", Class: release.ClassExternal}, {Name: "ours"}},
		Grants: []release.Grant{
			{Target: "minimal", Tools: []string{"echo"}, Roles: []string{"operator"}},
			{Target: "ref", Prompts: []string{"*"}, Resources: true, Roles: []string{"operator"}},
			{Target: "ours", Tools: []string{"echo"}, Prompts: []string{"*"}, Resources: true, Roles: []string{"operator"}}}}
	p := Compile(doc, c)
	as := func(client string) Principal {
		return Principal{Subject: "a", Tenant: "t1", Roles: []string{"operator"}, Method: "jwt", Client: client}
	}
	if !p.Allowed(as("idp-host"), "minimal", "echo") || p.Allowed(as("plain"), "minimal", "echo") {
		t.Error("tools")
	}
	if !p.AllowedPrompt(as("idp-host"), "ref", "x") || p.AllowedPrompt(as("plain"), "ref", "x") {
		t.Error("prompts")
	}
	if !p.AllowedResources(as("idp-host"), "ref") || p.AllowedResources(as("plain"), "ref") {
		t.Error("resources")
	}
	if !p.Allowed(as("plain"), "ours", "echo") || !p.AllowedPrompt(as("plain"), "ours", "x") || !p.AllowedResources(as("plain"), "ours") {
		t.Error("an internal target became host-only")
	}
	if got := p.VisibleTools(as("plain")); len(got) != 1 || got[0] != [2]string{"ours", "echo"} {
		t.Errorf("a client that is not the host sees %v", got)
	}
}

func TestAPolicyCompiledWithoutClientsGrantsNothing(t *testing.T) {
	p := Compile(&release.Document{TenantID: "t1", Grants: []release.Grant{{Target: "minimal", Tools: []string{"echo"}, Roles: []string{"operator"}}}}, nil)
	pr := Principal{Subject: "a", Tenant: "t1", Roles: []string{"operator"}, Method: "jwt", Client: "idp-host"}
	if p.Allowed(pr, "minimal", "echo") || len(p.VisibleTools(pr)) != 0 || p.Listed(pr) {
		t.Fatal("a policy with no clients file served a client")
	}
}
