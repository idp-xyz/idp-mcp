package registry

import (
	"encoding/json"
	"strings"
	"testing"

	"idp-mcp/internal/server"
)

func tool(t *testing.T, raw string) server.Tool {
	t.Helper()
	var tl server.Tool
	if err := json.Unmarshal([]byte(raw), &tl); err != nil {
		t.Fatal(err)
	}
	return tl
}

func TestTheDescriptionsOfAnExternalCatalogAreBoundedAndHaveNoInvisibleText(t *testing.T) {
	long := strings.Repeat("a", 101)
	cases := map[string]struct {
		tool, want string
	}{
		"a long description":          {`{"name":"x","description":"` + long + `","inputSchema":{"type":"object"}}`, "tool x: description is 101 bytes, more than the 100"},
		"a long title":                {`{"name":"x","title":"` + long + `","inputSchema":{"type":"object"}}`, "tool x: title is 101 bytes"},
		"a long property description": {`{"name":"x","inputSchema":{"type":"object","properties":{"q":{"type":"string","description":"` + long + `"}}}}`, "tool x: inputSchema/properties/q/description is 101 bytes"},
		"a long nested description":   {`{"name":"x","inputSchema":{"type":"object","properties":{"q":{"anyOf":[{"type":"string","description":"` + long + `"}]}}}}`, "inputSchema/properties/q/anyOf/0/description"},
		"a long output description":   {`{"name":"x","inputSchema":{"type":"object"},"outputSchema":{"type":"object","description":"` + long + `"}}`, "outputSchema/description"},
		"a zero-width character":      {"{\"name\":\"x\",\"description\":\"fine\\u200bhidden\",\"inputSchema\":{\"type\":\"object\"}}", "tool x: description has the invisible or control character U+200B"},
		"a tag character":             {"{\"name\":\"x\",\"description\":\"fine\\udb40\\udc41\",\"inputSchema\":{\"type\":\"object\"}}", "U+E0041"},
		"a bidirectional override":    {"{\"name\":\"x\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"q\":{\"description\":\"a\\u202eb\"}}}}", "inputSchema/properties/q/description has the invisible"},
		"a control character":         {"{\"name\":\"x\",\"description\":\"a\\u0007b\",\"inputSchema\":{\"type\":\"object\"}}", "U+0007"},
	}
	for name, c := range cases {
		err := CheckExternalDescriptions([]server.Tool{tool(t, c.tool)}, nil, 100)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := CheckExternalDescriptions([]server.Tool{tool(t, `{"name":"x","description":"Line one.\nLine two.\tTabbed. Ünïcödé is fine. `+strings.Repeat("a", 50)+`","inputSchema":{"type":"object","properties":{"description":{"type":"string"}}}}`)}, nil, 100); err != nil {
		t.Errorf("ordinary text was refused: %v", err)
	}
	if err := CheckExternalDescriptions(nil, []server.Prompt{{Name: "p", Description: long}}, 100); err == nil || !strings.Contains(err.Error(), "prompt p") {
		t.Errorf("a prompt description: %v", err)
	}
}

func TestTheDiffOfTwoCatalogsNamesWhatChanged(t *testing.T) {
	approved := &CatalogSnapshot{Digest: "a", Tools: []server.Tool{
		tool(t, `{"name":"keep","description":"d","inputSchema":{"type":"object"}}`),
		tool(t, `{"name":"words","description":"old","inputSchema":{"type":"object"}}`),
		tool(t, `{"name":"shape","description":"d","inputSchema":{"type":"object"}}`),
		tool(t, `{"name":"gone","description":"d","inputSchema":{"type":"object"}}`),
		tool(t, `{"name":"hint","description":"d","inputSchema":{"type":"object"},"annotations":{"readOnlyHint":true}}`)}}
	latest := &CatalogSnapshot{Digest: "b", Tools: []server.Tool{
		tool(t, `{"name":"keep","description":"d","inputSchema":{"type":"object"}}`),
		tool(t, `{"name":"words","description":"new","inputSchema":{"type":"object"}}`),
		tool(t, `{"name":"shape","description":"d","inputSchema":{"type":"object","properties":{"x":{}}}}`),
		tool(t, `{"name":"fresh","description":"d","inputSchema":{"type":"object"}}`),
		tool(t, `{"name":"hint","description":"d","inputSchema":{"type":"object"},"annotations":{"readOnlyHint":false},"_meta":{"a":1}}`)}}
	got, err := diffCatalogs(approved, latest)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(got.Tools)
	want := `[{"name":"fresh","kind":"added"},{"name":"gone","kind":"removed"},{"name":"hint","kind":"changed","fields":["_meta","annotations"]},` +
		`{"name":"shape","kind":"changed","fields":["inputSchema"]},{"name":"words","kind":"changed","fields":["description"]}]`
	if string(b) != want || got.Identical {
		t.Fatalf("%s", b)
	}
	same, _ := diffCatalogs(approved, approved)
	if !same.Identical || len(same.Tools) != 0 {
		t.Fatalf("%+v", same)
	}
	first, _ := diffCatalogs(nil, latest)
	if len(first.Tools) != 5 || first.Tools[0].Kind != "added" || first.Identical {
		t.Fatalf("with nothing approved everything is added: %+v", first)
	}
}

func TestAnExternalServersCapabilitiesLoseWhatWouldRelayItsPushes(t *testing.T) {
	got := externalCapabilities([]string{"tools", "prompts", "resources", "resources.subscribe", "resources.listChanged", "tasks", "completions"})
	if strings.Join(got, ",") != "tools,prompts,resources,completions" {
		t.Fatal(got)
	}
}
