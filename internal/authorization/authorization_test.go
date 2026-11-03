package authorization

import (
	"testing"

	"idp-mcp/internal/release"
)

func policy() *Policy {
	return Compile(&release.Document{TenantID: "t1", Grants: []release.Grant{
		{Target: "minimal", Tools: []string{"echo", "sum"}, Roles: []string{"operator"}},
		{Target: "minimal", Tools: []string{"sum"}, Roles: []string{"viewer"}},
		{Target: "reference", Tools: []string{"test_simple_text"}, Roles: []string{"operator"}},
	}})
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
	}})
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
