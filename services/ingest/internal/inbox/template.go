package inbox

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

// ErrTemplateNotFound is returned when a token resolves to a template_id
// that wasn't shipped with the running ingest binary. Handlers translate
// this to 503 — the URL is valid but the running version of the service
// can't process it; the operator needs to upgrade the deployment or pick
// a different template.
var ErrTemplateNotFound = errors.New("inbox template not registered")

// Template defines how a vendor-specific JSON payload maps onto an OCSF
// event. Each YAML file in services/ingest/internal/normalizer/templates/
// produces one Template; the filename stem (without .yaml) is the
// template_id stored in tenant_inbox_tokens.
//
// The mapping language is intentionally minimal — dot-path source field
// to dot-path OCSF field, plus a small set of severity translations and
// constants — because the goal is "stamp out webhook adapters in
// minutes" not "build a general-purpose ETL DSL". Anything more complex
// belongs in a real connector under services/connectors/app/connectors/.
type Template struct {
	// ID is the filename stem — must match tenant_inbox_tokens.template_id.
	ID string `yaml:"id"`
	// VendorName / ProductName populate ocsf.metadata.product so
	// downstream queries can filter by vendor without parsing tenant_uid.
	VendorName  string `yaml:"vendor_name"`
	ProductName string `yaml:"product_name"`

	// OCSFClass identifies the destination OCSF class (Authentication,
	// Security Finding, etc). We carry both the numeric class_uid and the
	// human-readable class_name to keep the published event self-describing.
	ClassUID  int    `yaml:"class_uid"`
	ClassName string `yaml:"class_name"`

	// Activity overrides the default activity_id (1 = "Create") — useful
	// for auth events where vendor traffic is mostly login/logout.
	ActivityID int `yaml:"activity_id,omitempty"`

	// FieldMap projects vendor JSON paths onto OCSF JSON paths. Both
	// sides use dot notation; arrays are addressed with `[N]`.
	FieldMap map[string]string `yaml:"field_map"`

	// SeverityMap translates vendor severity strings (case-insensitive)
	// to OCSF severity_id 0-6. The key is normalised to lower-case at
	// load time.
	SeverityMap map[string]int `yaml:"severity_map,omitempty"`

	// SeverityField — JSON path to the vendor's severity string. Default
	// "severity"; templates override for vendors that use "priority"
	// (PagerDuty), "level" (Cloudflare), etc.
	SeverityField string `yaml:"severity_field,omitempty"`

	// TimeField — JSON path to the vendor's event time. Default "time";
	// templates override for vendors that use "timestamp", "@timestamp",
	// "created_at", etc.
	TimeField string `yaml:"time_field,omitempty"`

	// MessageField — JSON path the wizard's "what happened" line is
	// pulled from. Default "message".
	MessageField string `yaml:"message_field,omitempty"`

	// Constants — fields stamped onto every event regardless of payload.
	// Useful for vendor-specific tags ("source": "pagerduty.events.v2")
	// that downstream detection content keys on.
	Constants map[string]any `yaml:"constants,omitempty"`
}

// Registry holds the loaded templates indexed by ID.
//
// Templates are loaded once at startup; the registry is read-only after
// that, so we can serve concurrent webhooks without a mutex.
type Registry struct {
	mu        sync.RWMutex
	templates map[string]*Template
}

// NewRegistry returns an empty registry. Call Load() to populate from disk.
func NewRegistry() *Registry {
	return &Registry{templates: make(map[string]*Template)}
}

// Load reads every *.yaml file in dir and registers it as a template.
// Files with malformed YAML are logged and skipped so a typo in one
// template doesn't take down the whole ingest service.
//
// dir is typically baked into the container image at
// /app/templates, but tests override to use a tmpdir.
func (r *Registry) Load(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("inbox: read template dir %s: %w", dir, err)
	}

	loaded := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		path := filepath.Join(dir, name)
		raw, err := os.ReadFile(path)
		if err != nil {
			log.Warn().Err(err).Str("path", path).Msg("inbox: skipping unreadable template")
			continue
		}
		t := &Template{}
		if err := yaml.Unmarshal(raw, t); err != nil {
			log.Warn().Err(err).Str("path", path).Msg("inbox: malformed template YAML")
			continue
		}
		// Default the ID to the filename stem — operators usually leave
		// the explicit `id:` blank and rely on the convention.
		if t.ID == "" {
			t.ID = strings.TrimSuffix(strings.TrimSuffix(name, ".yaml"), ".yml")
		}
		// Normalise severity keys.
		if len(t.SeverityMap) > 0 {
			normalised := make(map[string]int, len(t.SeverityMap))
			for k, v := range t.SeverityMap {
				normalised[strings.ToLower(strings.TrimSpace(k))] = v
			}
			t.SeverityMap = normalised
		}

		r.mu.Lock()
		r.templates[t.ID] = t
		r.mu.Unlock()
		loaded++
	}
	log.Info().Int("count", loaded).Str("dir", dir).Msg("inbox: templates loaded")
	return nil
}

// Get returns a template by ID, or ErrTemplateNotFound.
func (r *Registry) Get(id string) (*Template, error) {
	r.mu.RLock()
	t, ok := r.templates[id]
	r.mu.RUnlock()
	if !ok {
		return nil, ErrTemplateNotFound
	}
	return t, nil
}

// Register inserts a template programmatically. Used by tests.
func (r *Registry) Register(t *Template) {
	r.mu.Lock()
	r.templates[t.ID] = t
	r.mu.Unlock()
}

// IDs returns the registered template IDs (for debug/introspection).
func (r *Registry) IDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.templates))
	for k := range r.templates {
		out = append(out, k)
	}
	return out
}
