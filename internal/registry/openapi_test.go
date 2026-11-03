package registry

import (
	"bufio"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// documentedRoutes reads "METHOD /path" pairs from api/openapi.yaml: a path is a two-space key
// under paths:, an operation a four-space get/post/put/patch/delete key under it.
func documentedRoutes(t *testing.T) []string {
	f, err := os.Open("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pathRE := regexp.MustCompile(`^  (/[^:]*):\s*$`)
	opRE := regexp.MustCompile(`^    (get|post|put|patch|delete):`)
	var out []string
	in, cur := false, ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "paths:":
			in = true
		case in && line != "" && !strings.HasPrefix(line, " "):
			in = false
		case in && pathRE.MatchString(line):
			cur = pathRE.FindStringSubmatch(line)[1]
		case in && cur != "" && opRE.MatchString(line):
			out = append(out, strings.ToUpper(opRE.FindStringSubmatch(line)[1])+" "+cur)
		}
	}
	sort.Strings(out)
	return out
}

func TestOpenAPIDocumentsExactlyTheRoutes(t *testing.T) {
	served := (&API{}).Routes()
	sort.Strings(served)
	documented := documentedRoutes(t)
	want := map[string]bool{}
	for _, r := range documented {
		want[r] = true
	}
	have := map[string]bool{}
	for _, r := range served {
		have[r] = true
		if !want[r] {
			t.Errorf("served but not documented in api/openapi.yaml: %s", r)
		}
	}
	for _, r := range documented {
		if !have[r] {
			t.Errorf("documented but not served: %s", r)
		}
	}
	if len(served) < 20 {
		t.Fatalf("only %d routes found; the router listing is broken", len(served))
	}
}

// TestOpenAPIIsValidYAMLWithResolvableRefs parses the document for real and resolves every local
// $ref, so a broken spec cannot pass on the line-based route comparison alone.
func TestOpenAPIIsValidYAMLWithResolvableRefs(t *testing.T) {
	raw, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("api/openapi.yaml is not valid YAML: %v", err)
	}
	if doc["openapi"] != "3.1.0" {
		t.Fatalf("openapi version %v", doc["openapi"])
	}
	resolve := func(ref string) bool {
		var cur any = doc
		for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
			m, ok := cur.(map[string]any)
			if !ok {
				return false
			}
			if cur, ok = m[part]; !ok {
				return false
			}
		}
		return true
	}
	refs := 0
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if r, ok := x["$ref"].(string); ok {
				refs++
				if !strings.HasPrefix(r, "#/") || !resolve(r) {
					t.Errorf("unresolvable $ref %q", r)
				}
			}
			for _, c := range x {
				walk(c)
			}
		case []any:
			for _, c := range x {
				walk(c)
			}
		}
	}
	walk(doc)
	paths := doc["paths"].(map[string]any)
	ops := 0
	for _, p := range paths {
		for k := range p.(map[string]any) {
			if k == "get" || k == "post" {
				ops++
			}
		}
	}
	if ops != len((&API{}).Routes()) || refs < 30 {
		t.Fatalf("%d operations for %d routes, %d refs", ops, len((&API{}).Routes()), refs)
	}
}
