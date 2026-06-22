package inbox

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Registry tests focus on the load-from-disk contract because that's
// where the operator-facing failure modes live: a typo in one YAML
// file must not poison the whole registry, and severity keys must be
// case-folded so vendors that send "High" / "HIGH" / "high" all hit the
// same lookup.

func writeTemplate(t *testing.T, dir, name, body string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestRegistry_Load_ReadsValidTemplates(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "pagerduty.yaml", `
vendor_name: PagerDuty
product_name: Events API v2
class_uid: 2001
class_name: Security Finding
field_map:
  event.id: metadata.event_id
  event.title: finding.title
severity_field: event.urgency
severity_map:
  low: 2
  high: 4
  critical: 5
constants:
  source: pagerduty.events.v2
`)
	writeTemplate(t, dir, "opsgenie.yaml", `
vendor_name: Atlassian Opsgenie
product_name: Webhook v2
class_uid: 2001
class_name: Security Finding
field_map:
  alert.alertId: metadata.event_id
`)

	r := NewRegistry()
	if err := r.Load(dir); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	pd, err := r.Get("pagerduty")
	if err != nil {
		t.Fatalf("Get(pagerduty) failed: %v", err)
	}
	if pd.VendorName != "PagerDuty" {
		t.Errorf("vendor_name = %q", pd.VendorName)
	}
	if pd.ClassUID != 2001 {
		t.Errorf("class_uid = %d", pd.ClassUID)
	}
	if pd.FieldMap["event.id"] != "metadata.event_id" {
		t.Errorf("field_map missing or wrong: %v", pd.FieldMap)
	}

	if _, err := r.Get("opsgenie"); err != nil {
		t.Errorf("Get(opsgenie) failed: %v", err)
	}

	ids := r.IDs()
	if len(ids) != 2 {
		t.Errorf("IDs() = %v, want 2 entries", ids)
	}
}

func TestRegistry_Load_DefaultsIDFromFilename(t *testing.T) {
	// Operators rarely set an explicit `id:` — the filename stem is the
	// convention. Verify the registry honours it.
	dir := t.TempDir()
	writeTemplate(t, dir, "github-security-advisory.yaml", `
vendor_name: GitHub
class_uid: 2002
class_name: Vulnerability Finding
field_map: {}
`)
	r := NewRegistry()
	if err := r.Load(dir); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if _, err := r.Get("github-security-advisory"); err != nil {
		t.Errorf("ID not derived from filename: %v", err)
	}
}

func TestRegistry_Load_NormalisesSeverityKeys(t *testing.T) {
	// Vendor severity strings come in every casing imaginable; the load
	// step lowercases keys so the runtime lookup with strings.ToLower
	// always hits.
	dir := t.TempDir()
	writeTemplate(t, dir, "shouty.yaml", `
class_uid: 2001
class_name: Security Finding
field_map: {}
severity_map:
  CRITICAL: 5
  "  High  ": 4
  low: 2
`)
	r := NewRegistry()
	if err := r.Load(dir); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	tmpl, _ := r.Get("shouty")
	if tmpl.SeverityMap["critical"] != 5 {
		t.Errorf("CRITICAL not folded to lowercase: %v", tmpl.SeverityMap)
	}
	if tmpl.SeverityMap["high"] != 4 {
		t.Errorf("'  High  ' not trimmed/folded: %v", tmpl.SeverityMap)
	}
	if _, ok := tmpl.SeverityMap["CRITICAL"]; ok {
		t.Errorf("uppercase key still present: %v", tmpl.SeverityMap)
	}
}

func TestRegistry_Load_SkipsMalformedYAMLWithoutFailingTheRest(t *testing.T) {
	// One typo in pagerduty.yaml must not take down opsgenie.yaml — that's
	// what makes the registry safe to populate from a community-contributed
	// /app/templates dir.
	dir := t.TempDir()
	writeTemplate(t, dir, "broken.yaml", "this: is: not valid: yaml: ::::")
	writeTemplate(t, dir, "good.yaml", `
class_uid: 2001
class_name: Security Finding
field_map: {}
`)
	r := NewRegistry()
	if err := r.Load(dir); err != nil {
		t.Fatalf("Load returned error despite skip-on-bad-yaml contract: %v", err)
	}
	if _, err := r.Get("good"); err != nil {
		t.Errorf("good template missing after broken sibling: %v", err)
	}
	if _, err := r.Get("broken"); err == nil {
		t.Errorf("broken template should not be registered")
	}
}

func TestRegistry_Load_IgnoresNonYAMLFiles(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "README.md", "# templates")
	writeTemplate(t, dir, "config.json", `{"id":"x"}`)
	writeTemplate(t, dir, "good.yml", `
class_uid: 2001
class_name: Security Finding
field_map: {}
`)
	r := NewRegistry()
	if err := r.Load(dir); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(r.IDs()) != 1 {
		t.Errorf("non-YAML files leaked in: %v", r.IDs())
	}
}

func TestRegistry_Load_ErrorsOnMissingDir(t *testing.T) {
	r := NewRegistry()
	err := r.Load("/nonexistent/template/dir/" + strings.Repeat("x", 10))
	if err == nil {
		t.Fatalf("expected error for missing dir")
	}
}

func TestRegistry_Get_UnknownReturnsErrTemplateNotFound(t *testing.T) {
	r := NewRegistry()
	_, err := r.Get("does-not-exist")
	if !errors.Is(err, ErrTemplateNotFound) {
		t.Errorf("err = %v, want ErrTemplateNotFound", err)
	}
}

func TestRegistry_Register_AllowsTestsToInjectInMemory(t *testing.T) {
	// Test-only path. Confirms tests can register a template without a
	// real YAML file on disk — used by handler_test and apply_test.
	r := NewRegistry()
	r.Register(&Template{ID: "synthetic", ClassUID: 2001, ClassName: "Security Finding"})
	got, err := r.Get("synthetic")
	if err != nil {
		t.Fatalf("Get(synthetic) failed: %v", err)
	}
	if got.ClassUID != 2001 {
		t.Errorf("registered template not returned: %#v", got)
	}
}
