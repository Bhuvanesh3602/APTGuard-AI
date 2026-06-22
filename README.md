<div align="center">

<img width="500" height="170" alt="Et-Hack" src="https://github.com/user-attachments/assets/3c6f729f-9547-43bd-a36f-ae1ff8274a1f" />

# AiSOC-CNI
### AI-Driven Cyber Resilience for Critical National Infrastructure

[![License: MIT](https://img.shields.io/badge/License-MIT-22c55e.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Hackathon](https://img.shields.io/badge/ET%20Hackathon%202026-Cybersecurity%20Track-2563eb?style=flat-square)]()
[![Theme](https://img.shields.io/badge/Theme-Industrial%20Intelligence%20%7C%20National%20Security-f59e0b?style=flat-square)]()

**Built on [AiSOC](https://github.com/beenuar/AiSOC) (MIT) · Extended for India CNI · Team: Bhuvanesh**

</div>

---

## The Problem

India's critical national infrastructure is under sustained, escalating attack.

| Incident | Year | Impact |
|---|---|---|
| AIIMS Delhi ransomware | 2022 | Paralysed for 2+ weeks; patient records encrypted, surgeries postponed |
| CBSE data breach | 2024 | Examination records of millions compromised |
| CBSE coordinated APT attack | Jan 2026 | Emergency shutdowns across multiple states before board exams; student data exfiltrated |
| CERT-In total incidents | 2023 | **1.59 million** cybersecurity incidents handled — and climbing |

**The root cause is not the attacks. It is detection speed.**

- Average APT dwell time in government networks: **207 days**
- India's public sector: **70%+ systems on end-of-life IT infrastructure** (National Cyber Security Policy 2020)
- Current detection method: **signature-based** — useless against zero-day and custom APT malware
- By the time a signature exists for an attack, it has already succeeded *somewhere*

What India's CNI needs is a **behavioural intelligence layer** that detects anomalies from *how systems normally behave*, not from whether they match a known signature. And when a threat is confirmed, it needs to **respond autonomously in seconds**, not days.

---

## What We Built

An end-to-end **AI-powered Cyber Resilience platform** purpose-built for Indian Critical National Infrastructure sectors — Healthcare, Education, Power Grid, Finance, Government IT — that compresses the time from initial compromise to detection and response **from weeks to hours**.

### The Five Capabilities

| Capability | What It Does |
|---|---|
| **Behavioural Anomaly Detection** | Builds baseline profiles for users, devices, and OT nodes; continuously scores deviations across logs, network flows, and endpoint telemetry — no signatures required |
| **India APT Attribution & Prediction** | Maps observed attack patterns to known India-targeting APT campaigns; predicts the **next likely ATT&CK move** before it executes |
| **Autonomous Incident Response** | Executes sector-specific SOAR playbooks within seconds of high-confidence detection; human gates for blast-radius decisions above defined thresholds |
| **Government Vulnerability Prioritisation** | Amplifies CVE severity based on EoL asset context — a medium CVE on a Windows XP system is actually critical |
| **Cyber Resilience Digital Twin** | Attack path simulation on a cloned network graph — test red team scenarios without touching live production systems |

---

## Innovation Over Generic AiSOC

The platform is built on the open-source [AiSOC](https://github.com/beenuar/AiSOC) foundation. The following are the **novel additions** built for this hackathon:

### 1. India APT Intelligence Engine
- **CERT-In + NCIIPC RAG**: All CERT-In advisories and NCIIPC bulletins indexed in Qdrant vector store; agents retrieve relevant intelligence in real-time during investigation
- **India-targeting APT profiles**: Structured TTP databases for SideCopy, APT36 (Transparent Tribe), Lazarus Group (India ops), and Volt Typhoon — with specific techniques they use against Indian government, education, and healthcare targets
- **Next-Move Predictor**: When attack pattern `T1566.001 → T1059.001` is observed, the agent predicts `T1003.001 (LSASS dump)` is the next likely move and pre-stages a credential monitoring alert
- **Example output**: *"High confidence match: SideCopy Phase 2 lateral movement (T1021.002). This actor typically follows with T1078 (Valid Accounts) within 4–6 hours. Recommended pre-emptive action: force re-auth on domain accounts in affected subnet."*

### 2. OT/ICS Convergence Layer
- **Modbus + DNP3 connector**: Reads telemetry from industrial control systems; normalises into the same OCSF event schema as IT logs
- **OT UEBA**: Builds behavioural baselines for PLC command sequences and SCADA process values; anomalous command injection detected by deviation from baseline
- **IT→OT Pivot Detection**: Specifically detects the Stuxnet-class attack pattern where an attacker compromises an IT workstation and pivots into an isolated OT network via USB, shared drives, or historian software
- **Safety-first response**: OT playbooks always check whether isolation will trigger a safety interlock before executing — a constraint that generic SOAR platforms ignore

### 3. End-of-Life Asset Risk Amplifier
- **EoL factor**: CVE base CVSS × EoL multiplier (1.0× for current → 3.0× for EoL with no compensating control)
- **Example**: CVE-2024-1234 rated 6.5 (medium) on a patched Windows 11 system → rates 9.75 (critical) on Windows Server 2008 R2 with no compensating controls — which describes the majority of government networks
- **Dynamic remediation queue**: Continuously re-ranks the vulnerability backlog as new CVEs arrive and as asset EoL status changes
- **Realistic for government context**: Acknowledges that patching everything is impossible; prioritises the vulnerabilities that *actually matter* given real asset state

### 4. Cyber Resilience Digital Twin
- **Zero production risk**: Attack paths simulated on a Neo4j subgraph cloned from the live asset inventory — no production system is touched
- **Attack path queries**: *"If attacker compromises our DMZ web server (Apache 2.4.49, CVE-2021-41773), what is the highest-value asset reachable in 3 lateral moves?"*
- **Blast radius visualisation**: Every proposed automated action first runs on the Digital Twin; blast radius is computed before anything executes in production
- **Investment impact modelling**: *"If we segment OT network from IT, what percentage of current high-risk attack paths are eliminated?"*

### 5. CERT-In 6-Hour Compliance Automator
- **Regulatory context**: CERT-In's April 2022 Directions mandate reporting cybersecurity incidents within **6 hours** of detection. Most organisations currently miss this window.
- **Auto-generates the report**: LLM produces a CERT-In structured report from the Investigation Ledger artifacts (incident timeline, affected systems, indicators, initial response taken) within minutes of incident confirmation
- **Format compliance**: Fields mapped to CERT-In's prescribed incident report format
- **Audit trail**: Every auto-generated report includes a cryptographic hash of the underlying evidence it was generated from

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                     DATA SOURCES (India CNI)                         │
│                                                                      │
│  IT Logs          OT/ICS            Network            Cloud         │
│  (Windows/Linux)  (Modbus/DNP3/     (NetFlow/PCAP/     (AWS/Azure    │
│                    SCADA/PLCs)       Firewall)           GovCloud)    │
│                                                                      │
│  Endpoint         Identity           SaaS               Threat Intel  │
│  (osquery/EDR)   (LDAP/AD/          (M365/GWS)         (CERT-In/     │
│                   NIC eSign)                             NCIIPC/MISP) │
└────────────────────────────┬─────────────────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────────────┐
│                  INGEST & NORMALISE (Go · OCSF)                      │
│                                                                      │
│   OT/ICS Connector (NEW)  │  IT Connectors  │  IOC Enrichment       │
│   Modbus/DNP3 → OCSF      │  50 vendor taps │  (VT/AbuseIPDB/       │
│                            │                 │   GreyNoise)          │
└────────────────────────────┬─────────────────────────────────────────┘
                             │
                             ▼  Apache Kafka Spine
┌──────────────────────────────────────────────────────────────────────┐
│                DETECT & CORRELATE                                    │
│                                                                      │
│  ┌──────────────────────┐    ┌─────────────────────────────────┐    │
│  │     UEBA Engine      │    │       Fusion Engine             │    │
│  │  • User baselines    │    │  • LightGBM + Isolation Forest  │    │
│  │  • Device baselines  │    │  • Dedup (Bloom filter)         │    │
│  │  • OT node baselines │◄──►│  • Per-alert confidence score   │    │
│  │    (NEW)             │    │  • Risk-Based Alerting (RBA)    │    │
│  │  • Z-score anomaly   │    │  • Sector-aware weighting (NEW) │    │
│  └──────────────────────┘    └─────────────────────────────────┘    │
│                                         │                            │
│                              ┌──────────▼──────────┐               │
│                              │   Sigma/YARA/KQL     │               │
│                              │   Rule Engine        │               │
│                              │   + OT rules (NEW)   │               │
│                              │   + India APT rules   │               │
│                              │     (NEW)            │               │
│                              └──────────┬──────────┘                │
└─────────────────────────────────────────┼────────────────────────────┘
                                          │ Confirmed Alert
                                          ▼
┌──────────────────────────────────────────────────────────────────────┐
│           AI MULTI-AGENT INVESTIGATION  (LangGraph)                  │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                   RouterOrchestrator                         │   │
│  │                                                              │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │   │
│  │  │  DetectAgent │  │  TriageAgent │  │    HuntAgent     │  │   │
│  │  └──────────────┘  └──────────────┘  └──────────────────┘  │   │
│  │                                                              │   │
│  │  ┌────────────────────────────────────────────────────┐     │   │
│  │  │        India APT Attribution Agent  (NEW)          │     │   │
│  │  │  RAG over CERT-In + NCIIPC + ATT&CK ICS           │     │   │
│  │  │  → Actor match + next-move prediction              │     │   │
│  │  └────────────────────────────────────────────────────┘     │   │
│  │                                                              │   │
│  │  ┌────────────────────────────────────────────────────┐     │   │
│  │  │        APT Next-Move Predictor Agent  (NEW)        │     │   │
│  │  │  Observed kill chain → predicted T-codes           │     │   │
│  │  └────────────────────────────────────────────────────┘     │   │
│  │                                                              │   │
│  │  ┌─────────────────────┐  ┌──────────────────────────┐     │   │
│  │  │  OT Risk Agent (NEW)│  │  EoL Vuln Agent   (NEW) │     │   │
│  │  │  IT→OT pivot detect │  │  CVE × EoL amplification│     │   │
│  │  └─────────────────────┘  └──────────────────────────┘     │   │
│  │                                                              │   │
│  │  ┌─────────────────────────────────────────────────┐        │   │
│  │  │        CERT-In Compliance Agent  (NEW)          │        │   │
│  │  │  Auto-generate 6-hour mandatory report          │        │   │
│  │  └─────────────────────────────────────────────────┘        │   │
│  │                                                              │   │
│  │  ┌──────────────┐                                           │   │
│  │  │ RespondAgent │ ─────► Sector Playbooks (NEW)             │   │
│  │  └──────────────┘        Healthcare / Education /           │   │
│  │                           Power Grid / Govt IT              │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  Knowledge Stores:                                                   │
│  Neo4j (attack graph + Digital Twin)  │  Qdrant (CERT-In RAG)       │
│  PostgreSQL (cases + ledger)          │  Redis (cache + bloom)       │
└──────────────────────────────────────────────────────────────────────┘
                                          │
                                          ▼
┌──────────────────────────────────────────────────────────────────────┐
│                     RESPOND & REPORT                                 │
│                                                                      │
│  ┌────────────────────┐  ┌──────────────────┐  ┌─────────────────┐ │
│  │  Sector SOAR       │  │  Digital Twin    │  │  CERT-In        │ │
│  │  Playbooks  (NEW)  │  │  Simulation(NEW) │  │  Auto-Report    │ │
│  │                    │  │                  │  │  (NEW) — 6-hr   │ │
│  │  • Healthcare      │  │  Attack path     │  │  compliance     │ │
│  │  • Education       │  │  modelling on    │  │  window auto-   │ │
│  │  • Power Grid      │  │  cloned graph.   │  │  generated      │ │
│  │  • Govt IT         │  │  No prod touch.  │  │                 │ │
│  └────────────────────┘  └──────────────────┘  └─────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
                                          │
                                          ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    SOC CONSOLE  (Next.js 14)                         │
│                                                                      │
│  Investigation Rail │ Attack Graph │ Digital Twin │ OT Topology     │
│  CERT-In Compliance │ APT Timeline │ EoL Risk Map │ Anomaly Feed    │
└──────────────────────────────────────────────────────────────────────┘
```

### Service Map

| Service | Lang | Port | Role |
|---|---|---|---|
| `web` | Next.js 14 | 3000 | SOC console + Digital Twin UI + CERT-In dashboard |
| `api` | Python · FastAPI | 8000 | Core REST API + new CNI endpoints |
| `agents` | Python · LangGraph | 8001 | Multi-agent reasoning incl. 5 new India CNI agents |
| `fusion` | Python | 8003 | ML scoring (LightGBM + IsoForest) + sector-aware weights |
| `ueba` | Python | 8007 | User + OT device behaviour analytics |
| `actions` | Python | 8002 | SOAR with CNI sector playbooks + blast-radius Digital Twin check |
| `threatintel` | Python | 8005 | CERT-In + NCIIPC + TAXII / MISP / ATT&CK ICS |
| `ingest` | Go | 8081 | OCSF normalisation (IT + OT) |
| `enrichment` | Go | 8080 | IOC enrichment (VT, AbuseIPDB, GreyNoise) |
| `realtime` | Node.js | 8086 | WebSocket console feed |
| `ot-connector` | Python | 8092 | **NEW** — Modbus/DNP3/SCADA → OCSF |
| `digital-twin` | Python | 8093 | **NEW** — Attack path simulation on Neo4j clone |
| `certin-reporter` | Python | 8094 | **NEW** — 6-hour CERT-In mandatory report generator |
| `eol-prioritiser` | Python | 8095 | **NEW** — CVE × EoL asset amplification scoring |

---

## What Was Removed from AiSOC (and Why)

| Removed Component | Reason |
|---|---|
| `services/honeytokens/` | Not in CNI evaluation criteria; adds deployment weight |
| `services/purple-team/` | Replaced by Digital Twin — same simulation goal, integrated approach |
| `services/slack-bot/` | Not needed for demo; adds configuration complexity |
| `services/teams-bot/` | Same |
| `services/mcp/` | MCP integration not part of hackathon deliverables |
| `services/osquery-extensions/` | Replaced by OT/ICS connector |
| `infra/fly/`, `infra/railway/`, `infra/render/`, `infra/coolify/` | Single Docker Compose demo path retained |
| 50+ irrelevant SaaS connectors (Salesforce, Jira, Tines, etc.) | Replaced with CNI-relevant connectors |
| Marketing landing page | Console-first experience |
| `apps/docs/` Docusaurus site | Architecture docs retained as markdown; site removed |
| `scripts/wet_eval*` | External cloud eval not needed for hackathon |
| `marketplace/` and plugin registry | Not relevant to threat detection demo |

---

## What Was Built (New Files)

### New Services

```
services/
├── ot-connector/          # Modbus/DNP3/SCADA → OCSF normaliser
│   ├── app/main.py
│   ├── app/protocols/
│   │   ├── modbus.py      # Modbus TCP packet parser
│   │   ├── dnp3.py        # DNP3 application layer parser
│   │   └── scada.py       # Generic SCADA telemetry normaliser
│   └── app/ocsf/          # OT → OCSF event mapper
│
├── digital-twin/          # Attack path simulation
│   ├── app/main.py
│   ├── app/graph/
│   │   ├── clone.py       # Clones live Neo4j asset graph into isolated subgraph
│   │   ├── paths.py       # Cypher-based lateral movement path finder
│   │   └── blast.py       # Blast radius calculator per proposed action
│   └── app/api/           # REST endpoints for twin queries
│
├── certin-reporter/       # CERT-In 6-hour compliance report generator
│   ├── app/main.py
│   ├── app/templates/     # CERT-In prescribed report format fields
│   ├── app/generator.py   # LLM-structured report from Investigation Ledger
│   └── app/hash.py        # Evidence hash-chain for report integrity
│
└── eol-prioritiser/       # CVE × EoL amplification scoring
    ├── app/main.py
    ├── app/eol_db.py      # EoL dates for OS versions / software (offline DB)
    ├── app/amplifier.py   # CVSS × EoL factor calculator (1.0–3.0×)
    └── app/queue.py       # Dynamic risk-ranked remediation queue generator
```

### New AI Agents

```
services/agents/app/agents/
├── india_apt_agent.py        # APT actor attribution via CERT-In RAG
├── apt_prediction_agent.py   # Next ATT&CK technique prediction from observed chain
├── ot_risk_agent.py          # IT→OT pivot risk assessment
├── eol_vuln_agent.py         # EoL-amplified vulnerability triage
└── certin_agent.py           # CERT-In report drafting from ledger artifacts
```

### New Detection Rulesets

```
detections/
├── ot/                       # OT/ICS Sigma rules
│   ├── modbus-replay.yaml    # Modbus packet replay attack
│   ├── plc-command-inject.yaml
│   ├── scada-anomaly-process-value.yaml
│   └── it-to-ot-pivot.yaml  # Engineering workstation → PLC access
│
├── india-apt/                # India-targeting APT TTPs
│   ├── sidecopy-lnk-dropper.yaml
│   ├── apt36-spearphish-macro.yaml
│   ├── lazarus-swift-targeting.yaml
│   └── volttyphoon-living-off-land.yaml
│
├── eol-exploitation/         # CVEs commonly exploited on EoL govt systems
│   ├── eternalblue-ms17-010.yaml
│   ├── printnightmare-cve-2021-34527.yaml
│   └── log4shell-cve-2021-44228.yaml
│
└── cnf-ransomware/           # CNI-sector ransomware indicators
    ├── lockbit-healthcare.yaml
    ├── education-data-staging.yaml
    └── ot-ransomware-wannacry-variant.yaml
```

### New Sector Playbooks

```
playbooks/cni/
├── healthcare-ransomware.yaml      # AIIMS-class: isolate non-critical, preserve ICU nets
├── education-databreach.yaml       # CBSE-class: freeze exam data, notify board, preserve evidence
├── powergrid-ot-incident.yaml      # Safety-first OT isolation + manual override enable
└── govt-credential-compromise.yaml # AD quarantine + session revocation + lateral containment
```

### New Threat Intelligence Sources

```
threat-intel/
├── india-apt-profiles/
│   ├── sidecopy.json          # TTP profile: targets Indian defence/education
│   ├── apt36.json             # TTP profile: Transparent Tribe, Pakistan-nexus
│   ├── lazarus-india.json     # TTP profile: DPRK ops targeting Indian finance
│   └── volttyphoon-india.json # TTP profile: China-nexus CNI targeting
│
├── certin-advisories/         # CERT-In advisories (RAG-indexed)
│   └── [PDF/HTML corpus]      # Indexed into Qdrant at startup
│
└── nciipc-bulletins/          # NCIIPC threat bulletins
    └── [structured JSON]
```

### New API Endpoints

| Method | Endpoint | Service | Purpose |
|---|---|---|---|
| `POST` | `/api/v1/certin/report/{case_id}` | certin-reporter | Generate CERT-In report for a case |
| `GET` | `/api/v1/certin/report/{case_id}` | certin-reporter | Retrieve generated report (PDF/JSON) |
| `POST` | `/api/v1/digital-twin/simulate` | digital-twin | Run attack path simulation |
| `GET` | `/api/v1/digital-twin/paths/{asset_id}` | digital-twin | Get reachable assets from a compromised node |
| `POST` | `/api/v1/digital-twin/blast-radius` | digital-twin | Compute blast radius for a proposed SOAR action |
| `GET` | `/api/v1/eol-risk/queue` | eol-prioritiser | Get dynamic EoL-amplified remediation queue |
| `GET` | `/api/v1/eol-risk/asset/{asset_id}` | eol-prioritiser | Get EoL risk score for a specific asset |
| `GET` | `/api/v1/apt/attribution/{case_id}` | agents | Get APT actor attribution for a case |
| `GET` | `/api/v1/apt/prediction/{case_id}` | agents | Get predicted next ATT&CK moves |

### New Console Pages

| Page | Route | What |
|---|---|---|
| Digital Twin | `/digital-twin` | Interactive attack path graph + simulation runner |
| OT Topology | `/ot-topology` | Live OT network map with anomaly overlay |
| CERT-In Compliance | `/compliance/certin` | Report status, auto-generate, download |
| APT Intelligence | `/threat-intel/apt` | India APT profiles + active campaign tracking |
| EoL Risk Map | `/vulnerability/eol` | Asset inventory with EoL amplified risk scores |

---

## Evaluation Criteria — How We Score

| Criterion | Implementation | Target Metric |
|---|---|---|
| **Anomaly detection rate** | UEBA Z-score + LightGBM on CIC-IDS-2017 | DR > 95%, FPR < 2% |
| **False positive rate** | Cross-fire FP gate across all 816+ detection rules | FPR < 5% per rule |
| **APT attribution accuracy** | India APT Agent + CERT-In RAG + MITRE mapping | T-code (technique level) precision |
| **Incident response automation** | Sector playbooks with SOAR executor + Digital Twin blast check | > 80% playbook steps autonomous |
| **MTTD improvement** | UEBA baseline detection vs. signature-only baseline (CIC-IDS-2017) | Hours vs. weeks |
| **MTTR improvement** | SOAR auto-containment vs. manual response simulation | Minutes vs. days |
| **Full auditability** | Investigation Ledger: every prompt, tool call, evidence, rationale | 100% step traceability |

---

## Running the Benchmark

The project evaluates against the **CIC-IDS-2017** network intrusion detection dataset (University of New Brunswick) — the standard benchmark for network anomaly detection research.

```bash
# Download dataset (already scripted)
python scripts/datasets/download_cicids.py

# Run anomaly detection evaluation
python scripts/run_evals.py --suite anomaly_detection --out eval_report.json

# Run APT attribution accuracy test
pytest services/agents/tests/test_india_apt_accuracy.py -v

# Run SOAR automation coverage test
pytest services/agents/tests/test_playbook_automation.py -v

# Run full eval harness (all suites)
python scripts/run_evals.py --out eval_report.json
```

---

## Quick Start (Demo)

### Prerequisites

- Docker 24+ with Compose v2
- 8 GB RAM minimum allocated to Docker
- An Anthropic or OpenAI API key (for LLM reasoning)

### 1. Configure

```bash
cp .env.example .env
```

Minimum required in `.env`:
```env
ANTHROPIC_API_KEY=sk-ant-...    # or OPENAI_API_KEY=sk-...
AISOC_DEV_MODE=true
```

### 2. Launch

```bash
docker compose up -d --build
pnpm seed:demo
pnpm aisoc:doctor          # health check before logging in
```

### 3. Open the Console

```
http://localhost:3000/dashboard
Login: admin@aisoc.local / changeme
```

### 4. Demo Scenarios

The seed loads three pre-built CNI attack scenarios based on real India incidents:

| ID | Based On | Attack | Sector | Start URL |
|---|---|---|---|---|
| `CNI-001` | AIIMS Delhi 2022 | LockBit 3.0 ransomware via phishing email → lateral movement → encryption | Healthcare | `/cases/CNI-001?tab=ledger` |
| `CNI-002` | CBSE 2026 breach | APT36 spear-phish macro → credential theft → exam database exfil | Education | `/cases/CNI-002?tab=ledger` |
| `CNI-003` | India power grid probe | IT workstation compromise → historian software → PLC command injection | Power/OT | `/cases/CNI-003?tab=graph` |

```bash
# Jump directly to a running investigation:
open http://localhost:3000/cases/CNI-001?tab=ledger   # Healthcare ransomware
open http://localhost:3000/cases/CNI-002?tab=ledger   # Education APT breach
open http://localhost:3000/cases/CNI-003?tab=graph    # Power grid attack path
open http://localhost:3000/digital-twin               # Digital Twin simulator
open http://localhost:3000/compliance/certin          # CERT-In report dashboard
```

### 5. Key Service URLs

| Surface | URL |
|---|---|
| SOC Console | http://localhost:3000/dashboard |
| Digital Twin | http://localhost:3000/digital-twin |
| OT Topology | http://localhost:3000/ot-topology |
| CERT-In Reports | http://localhost:3000/compliance/certin |
| APT Intelligence | http://localhost:3000/threat-intel/apt |
| API Docs (Swagger) | http://localhost:8000/docs |
| Agents API | http://localhost:8001/docs |
| Digital Twin API | http://localhost:8093/docs |
| Neo4j Browser | http://localhost:7474 (neo4j / neo4j_dev_secret) |
| Kafka UI | http://localhost:8090 |

---

## Full Project Layout (Post-Cleanup)

```
AiSOC-CNI/
│
├── apps/
│   └── web/                          # SOC Console (Next.js 14)
│       └── src/app/
│           ├── (app)/dashboard/      # Main SOC console
│           ├── (app)/alerts/         # Alert queue + Investigation Rail
│           ├── (app)/cases/          # Case management + Ledger replay
│           ├── (app)/digital-twin/   # NEW: Digital Twin visualisation
│           ├── (app)/ot-topology/    # NEW: OT network map
│           ├── (app)/compliance/
│           │   └── certin/           # NEW: CERT-In report dashboard
│           └── (app)/threat-intel/
│               └── apt/              # NEW: India APT profiles + campaigns
│
├── services/
│   ├── api/                          # Core REST API (FastAPI)
│   ├── agents/                       # LangGraph multi-agent system
│   │   └── app/agents/
│   │       ├── detect_agent.py
│   │       ├── triage_agent.py
│   │       ├── hunt_agent.py
│   │       ├── respond_agent.py
│   │       ├── india_apt_agent.py        # NEW
│   │       ├── apt_prediction_agent.py   # NEW
│   │       ├── ot_risk_agent.py          # NEW
│   │       ├── eol_vuln_agent.py         # NEW
│   │       └── certin_agent.py           # NEW
│   ├── fusion/                       # ML scoring engine
│   ├── ueba/                         # Behavioural analytics (IT + OT)
│   ├── actions/                      # SOAR + sector playbooks
│   ├── threatintel/                  # CERT-In + NCIIPC + MITRE ATT&CK ICS
│   ├── ingest/                       # Go OCSF normaliser
│   ├── enrichment/                   # IOC enrichment
│   ├── realtime/                     # WebSocket feed
│   ├── ot-connector/                 # NEW: Modbus/DNP3/SCADA → OCSF
│   ├── digital-twin/                 # NEW: Attack path simulation
│   ├── certin-reporter/              # NEW: 6-hour compliance report
│   └── eol-prioritiser/              # NEW: CVE × EoL amplification
│
├── detections/
│   ├── endpoint/                     # Existing endpoint Sigma rules
│   ├── network/                      # Existing network rules
│   ├── cloud/                        # Existing cloud rules
│   ├── ot/                           # NEW: OT/ICS/SCADA detection rules
│   ├── india-apt/                    # NEW: SideCopy, APT36, Lazarus TTPs
│   ├── eol-exploitation/             # NEW: EoL-targeted CVE detection
│   └── cnf-ransomware/               # NEW: CNI-sector ransomware indicators
│
├── playbooks/
│   ├── community/                    # Existing community playbooks
│   └── cni/                          # NEW: Sector-specific CNI playbooks
│       ├── healthcare-ransomware.yaml
│       ├── education-databreach.yaml
│       ├── powergrid-ot-incident.yaml
│       └── govt-credential-compromise.yaml
│
├── threat-intel/
│   ├── india-apt-profiles/           # NEW: SideCopy, APT36, Lazarus, Volt Typhoon TTPs
│   ├── certin-advisories/            # NEW: CERT-In advisory corpus (RAG-indexed)
│   └── nciipc-bulletins/             # NEW: NCIIPC threat bulletins
│
├── scripts/
│   ├── datasets/                     # CIC-IDS-2017 download + preprocessing
│   │   └── download_cicids.py
│   ├── run_evals.py                  # Evaluation harness
│   ├── seed_cnf_demo.py              # NEW: Seeds CNI-001/002/003 scenarios
│   └── generate_certin_report.py     # NEW: CERT-In report CLI
│
├── docker-compose.yml                # Full stack
├── docker-compose.demo.yml           # NEW: Slim demo (no heavy stores)
├── .env.example
└── README.md                         # This file
```

---

## Removed Infra (Not Needed for Demo)

The following deployment targets were removed to keep the project focused on the demo:

- `infra/fly/` — Fly.io multi-app deployment
- `infra/railway/` — Railway PaaS config
- `infra/render/` — Render blueprint
- `infra/coolify/` — Coolify self-hosted PaaS
- `infra/terraform/` — AWS/GCP/Azure Terraform skeletons
- `infra/cloudflare/` — Cloudflare tunnel scripts

For production deployment, the original `infra/helm/` (Kubernetes) chart remains intact.

---

## Team & Attribution

**ET Hackathon 2026 — Cybersecurity / Industrial Intelligence / National Security**

Team member: Bhuvanesh (GitHub: [Bhuvanesh3602](https://github.com/Bhuvanesh3602))

Built on top of [AiSOC](https://github.com/beenuar/AiSOC) open-source platform (MIT license).

New components authored for this hackathon:
- India APT Intelligence Engine (CERT-In RAG + attribution + prediction agents)
- OT/ICS Convergence Layer (Modbus/DNP3 connector + OT UEBA baselines)
- End-of-Life Asset Risk Amplifier
- Cyber Resilience Digital Twin
- CERT-In 6-Hour Compliance Automator
- Sector-specific CNI playbooks (Healthcare, Education, Power Grid, Government IT)
- CIC-IDS-2017 benchmark evaluation pipeline

---

## References

- CERT-In Annual Report 2023
- NCIIPC Guidelines for Critical Information Infrastructure Protection
- MITRE ATT&CK v14 — Enterprise Matrix + ICS Matrix
- India National Cyber Security Policy 2020
- CIC-IDS-2017 Dataset — University of New Brunswick (benchmark evaluation)
- Cisco Talos / Seqrite Labs — SideCopy and APT36 India-targeting research
- CERT-In Advisory CIAD-2022-0047 — AIIMS Delhi incident
- CERT-In Directions 2022 — 6-hour mandatory incident reporting requirement

---

## License

[MIT](LICENSE) — AiSOC base platform © 2024–present AiSOC contributors.
Hackathon extensions © 2026 Bhuvanesh.
# APTGuard-AI
