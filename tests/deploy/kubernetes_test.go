// Package deploy checks deploy/kubernetes for internal consistency: every manifest parses, is in the
// idp-mcp namespace, references Secrets and ConfigMaps that exist, mounts what its file settings
// point at, is hardened, and the network policy is default-deny with the gateway reachable on its
// MCP port only. No cluster is involved (the reference host has none).
package deploy

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const dir = "../../deploy/kubernetes"

type doc = map[string]any

func load(t *testing.T, name string) []doc {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	var out []doc
	for {
		var d doc
		if err := dec.Decode(&d); errors.Is(err, io.EOF) {
			return out
		} else if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if d != nil {
			out = append(out, d)
		}
	}
}

func get(d any, path ...string) any {
	for _, p := range path {
		m, ok := d.(doc)
		if !ok {
			return nil
		}
		d = m[p]
	}
	return d
}

func str(d any, path ...string) string { s, _ := get(d, path...).(string); return s }

func list(d any, path ...string) []any { l, _ := get(d, path...).([]any); return l }

func name(d doc) string { return str(d, "kind") + "/" + str(d, "metadata", "name") }

type manifests struct {
	docs       []doc
	configMaps map[string]doc
	secrets    map[string]map[string]bool // name -> keys (from secrets.example.yaml)
	byKind     map[string][]doc
}

func loadAll(t *testing.T) *manifests {
	t.Helper()
	k := load(t, "kustomization.yaml")[0]
	m := &manifests{configMaps: map[string]doc{}, secrets: map[string]map[string]bool{}, byKind: map[string][]doc{}}
	for _, r := range list(k, "resources") {
		if r.(string) == "secrets.example.yaml" {
			t.Fatal("placeholder secrets must not be applied")
		}
		for _, d := range load(t, r.(string)) {
			m.docs = append(m.docs, d)
			m.byKind[str(d, "kind")] = append(m.byKind[str(d, "kind")], d)
			if str(d, "kind") == "ConfigMap" {
				m.configMaps[str(d, "metadata", "name")] = d
			}
		}
	}
	for _, s := range load(t, "secrets.example.yaml") {
		keys := map[string]bool{}
		for k := range get(s, "stringData").(doc) {
			keys[k] = true
		}
		m.secrets[str(s, "metadata", "name")] = keys
	}
	if len(m.docs) < 10 || str(k, "namespace") != "idp-mcp" {
		t.Fatalf("%d documents, namespace %q", len(m.docs), str(k, "namespace"))
	}
	return m
}

func TestEveryManifestIsNamedAndNamespaced(t *testing.T) {
	m := loadAll(t)
	for _, d := range m.docs {
		if str(d, "apiVersion") == "" || str(d, "kind") == "" || str(d, "metadata", "name") == "" {
			t.Errorf("incomplete object: %v", d)
		}
		if str(d, "kind") != "Namespace" && str(d, "metadata", "namespace") != "idp-mcp" {
			t.Errorf("%s: namespace %q", name(d), str(d, "metadata", "namespace"))
		}
	}
	ns := m.byKind["Namespace"][0]
	if str(ns, "metadata", "labels", "pod-security.kubernetes.io/enforce") != "restricted" {
		t.Error("namespace does not enforce the restricted pod security standard")
	}
}

func podSpec(d doc) doc {
	spec, _ := get(d, "spec", "template", "spec").(doc)
	return spec
}

func TestWorkloadsAreHardenedAndWired(t *testing.T) {
	m := loadAll(t)
	for _, d := range append(m.byKind["Deployment"], m.byKind["Job"]...) {
		spec := podSpec(d)
		if spec == nil {
			t.Fatalf("%s: no pod spec", name(d))
		}
		if v, _ := spec["automountServiceAccountToken"].(bool); v || spec["automountServiceAccountToken"] == nil {
			t.Errorf("%s: service account token must not be mounted", name(d))
		}
		if v, _ := get(spec, "securityContext", "runAsNonRoot").(bool); !v {
			t.Errorf("%s: runAsNonRoot", name(d))
		}
		if str(spec, "securityContext", "seccompProfile", "type") != "RuntimeDefault" {
			t.Errorf("%s: seccomp", name(d))
		}
		volumes := map[string]doc{}
		for _, v := range list(spec, "volumes") {
			vol := v.(doc)
			volumes[str(vol, "name")] = vol
			if sec := get(vol, "secret"); sec != nil {
				sname := str(sec, "secretName")
				if m.secrets[sname] == nil {
					t.Errorf("%s: volume %s references unknown Secret %s", name(d), str(vol, "name"), sname)
				}
				for _, it := range list(sec, "items") {
					if !m.secrets[sname][str(it, "key")] {
						t.Errorf("%s: Secret %s has no key %s", name(d), sname, str(it, "key"))
					}
				}
			}
		}
		for _, c := range list(spec, "containers") {
			c := c.(doc)
			cn := name(d) + "/" + str(c, "name")
			if str(c, "image") != "idp-mcp" {
				t.Errorf("%s: image %q is not overridden through kustomization images", cn, str(c, "image"))
			}
			sc := get(c, "securityContext")
			if v, _ := get(sc, "allowPrivilegeEscalation").(bool); v || get(sc, "allowPrivilegeEscalation") == nil {
				t.Errorf("%s: allowPrivilegeEscalation", cn)
			}
			if v, _ := get(sc, "readOnlyRootFilesystem").(bool); !v {
				t.Errorf("%s: readOnlyRootFilesystem", cn)
			}
			if drops := list(sc, "capabilities", "drop"); len(drops) != 1 || drops[0] != "ALL" {
				t.Errorf("%s: capabilities not dropped", cn)
			}
			if get(c, "resources", "limits") == nil {
				t.Errorf("%s: no resource limits", cn)
			}
			if str(d, "kind") == "Deployment" && (get(c, "readinessProbe") == nil || get(c, "livenessProbe") == nil) {
				t.Errorf("%s: probes missing", cn)
			}
			mounts := map[string]string{} // mountPath -> volume
			for _, vm := range list(c, "volumeMounts") {
				if volumes[str(vm, "name")] == nil {
					t.Errorf("%s: mount of unknown volume %s", cn, str(vm, "name"))
				}
				mounts[str(vm, "mountPath")] = str(vm, "name")
			}
			for _, e := range list(c, "env") {
				if ref := get(e, "valueFrom", "secretKeyRef"); ref != nil {
					if !m.secrets[str(ref, "name")][str(ref, "key")] {
						t.Errorf("%s: env %s references Secret %s key %s, not in secrets.example.yaml", cn, str(e, "name"), str(ref, "name"), str(ref, "key"))
					}
				}
			}
			for _, ef := range list(c, "envFrom") {
				cm := m.configMaps[str(ef, "configMapRef", "name")]
				if cm == nil {
					t.Errorf("%s: envFrom unknown ConfigMap %s", cn, str(ef, "configMapRef", "name"))
					continue
				}
				// every *_FILE setting must point into a mounted volume
				for k, v := range get(cm, "data").(doc) {
					if !strings.HasSuffix(k, "_FILE") {
						continue
					}
					if _, ok := mounts[filepath.Dir(v.(string))]; !ok {
						t.Errorf("%s: %s=%s is not under a volume mount", cn, k, v)
					}
				}
			}
		}
	}
	for _, d := range m.byKind["Deployment"] {
		if str(d, "metadata", "labels", "app.kubernetes.io/component") == "gateway" {
			if r, _ := get(d, "spec", "replicas").(int); r != 1 || str(d, "spec", "strategy", "type") != "Recreate" {
				t.Errorf("%s: a gateway record has one attested status; replicas must be 1 with Recreate", name(d))
			}
		}
	}
}

func labelsMatch(selector doc, labels doc) bool {
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return len(selector) > 0
}

func TestSelectorsResolveToExactlyOneWorkload(t *testing.T) {
	m := loadAll(t)
	for _, s := range append(m.byKind["Service"], m.byKind["PodDisruptionBudget"]...) {
		sel, _ := get(s, "spec", "selector").(doc)
		if ml, ok := sel["matchLabels"].(doc); ok {
			sel = ml
		}
		n := 0
		for _, d := range m.byKind["Deployment"] {
			if labels, _ := get(d, "spec", "template", "metadata", "labels").(doc); labelsMatch(sel, labels) {
				n++
			}
		}
		if n != 1 {
			t.Errorf("%s: selector %v matches %d deployments", name(s), sel, n)
		}
	}
}

func TestNetworkPolicyIsDefaultDenyWithTheGatewayOnItsPortOnly(t *testing.T) {
	m := loadAll(t)
	var defaultDeny, gateway, registry doc
	for _, p := range m.byKind["NetworkPolicy"] {
		switch str(p, "metadata", "name") {
		case "default-deny":
			defaultDeny = p
		case "gateway":
			gateway = p
		case "registry":
			registry = p
		}
	}
	if defaultDeny == nil || gateway == nil || registry == nil {
		t.Fatal("default-deny, gateway and registry policies are required")
	}
	if sel, _ := get(defaultDeny, "spec", "podSelector").(doc); len(sel) != 0 || len(list(defaultDeny, "spec", "policyTypes")) != 2 {
		t.Error("default-deny must select every pod for ingress and egress")
	}
	ports := func(p doc, direction string) []any {
		var out []any
		for _, rule := range list(p, "spec", direction) {
			for _, port := range list(rule, "ports") {
				out = append(out, get(port, "port"))
			}
		}
		return out
	}
	if ps := ports(gateway, "ingress"); len(ps) != 1 || ps[0] != 3220 {
		t.Errorf("gateway ingress ports %v", ps)
	}
	if ps := ports(registry, "ingress"); len(ps) != 1 || ps[0] != 8250 {
		t.Errorf("registry ingress ports %v", ps)
	}
	for _, p := range []doc{gateway, registry} {
		if len(list(p, "spec", "egress")) == 0 || len(list(p, "spec", "policyTypes")) != 2 {
			t.Errorf("%s: egress must be restricted too", name(p))
		}
		for _, rule := range list(p, "spec", "egress") {
			for _, to := range list(rule, "to") {
				if get(to, "namespaceSelector") == nil && get(to, "podSelector") == nil && get(to, "ipBlock") == nil {
					t.Errorf("%s: an egress rule without a peer allows everything", name(p))
				}
				if cidr := str(to, "ipBlock", "cidr"); cidr == "0.0.0.0/0" {
					t.Errorf("%s: egress to 0.0.0.0/0", name(p))
				}
			}
		}
	}
}
