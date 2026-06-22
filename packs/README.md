# AiSOC Osquery Pack Format

This directory contains curated osquery packs in the AiSOC YAML format.

## Schema

Each pack file is a YAML document with the following top-level keys:

```yaml
id: aisoc-fim-baseline           # Unique pack identifier (kebab-case)
name: AiSOC File Integrity Baseline
version: 1.0.0                   # Semver
platforms: [linux, darwin]       # Supported platforms: linux | darwin | windows
description: |
  Human-readable description of what this pack covers.
discovery:
  - SELECT pid FROM processes WHERE name = 'osqueryd';
queries:
  <query_name>:
    sql: SELECT ...              # SQL query string
    interval: 60                 # Poll interval in seconds
    severity: high               # info | low | medium | high
    description: ...
    mitre: [T1098]               # Optional MITRE ATT&CK technique IDs
    references:
      - https://attack.mitre.org/techniques/T1098/
file_paths:                      # Optional FIM paths section
  <group_name>:
    - /path/to/watch
    - /path/with/%%/glob         # %% = recursive glob
```

## Compiling to Canonical Osquery JSON

The `pack_loader` (in `services/api/app/services/pack_loader.py`) reads all YAML files and exposes them as validated `OsqueryPack` Pydantic models.

The `pack_resolver` (in `services/osquery-tls/app/services/pack_resolver.py`) takes an enrolled node's tenant ID, looks up assigned packs, and compiles them into the osquery TLS config JSON shape:

```json
{
  "schedule": { ... },
  "packs": { "<pack_id>": { ... } },
  "file_paths": { ... }
}
```

## Rendering for osctrl / FleetDM

Use `GET /v1/packs/{id}/render?format=osctrl|fleetdm|osquery-json` to download a pack in the native format for manual import into your fleet manager. See [docs/packs/distribution.md](../apps/docs/docs/packs/distribution.md) for import walkthroughs.

## Curated Packs

| ID | Description | Platforms | MITRE |
|----|-------------|-----------|-------|
| `aisoc-fim-baseline` | Critical config/credential file integrity | linux, darwin | T1098, T1078 |
| `aisoc-fim-credentials` | Cloud/k8s credential file monitoring | linux, darwin | T1552 |
| `aisoc-attck-persistence` | Cron, systemd, launchd, Run key persistence | linux, darwin | T1547, T1543 |
| `aisoc-attck-defense-evasion` | Disabled services, cleared logs | linux, darwin | T1562, T1070 |
| `aisoc-inventory-baseline` | OS/kernel/package inventory (info) | linux, darwin, windows | — |

## Contributing

1. Copy an existing pack as a template.
2. Validate with `python scripts/validate_packs.py packs/<your-pack>.yaml`.
3. Add a fixture under `detections/fixtures/` if the pack drives detections.
4. Update the table above and open a PR.
