# Meridian Emulation

ATT&CK technique emulation and detection validation pipeline with two integration paths:
[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) for host-based execution
and [MITRE Caldera](https://github.com/apache/caldera) for agent-based adversary emulation.
Both pull technique priorities from the Meridian Risk Scoring API and validate against
CyberGraph-AD for closed-loop purple team coverage analysis.

## What it does

**Meridian Emulation** closes the loop in the AI security engineering pipeline by
answering: *do your detections actually fire against the techniques your threat
intelligence says you're exposed to?*

```
Meridian /controls/gaps
        │  Techniques with no active mitigation
        ▼
┌───────────────────────┬──────────────────────────┐
│  Atomic Red Team path │  Caldera path            │
│                       │                          │
│  Technique Selector   │  caldera_client.py       │
│  ↓                    │  ↓                       │
│  Emulation Runner     │  Adversary profile →     │
│  (subprocess)         │  Caldera REST API        │
│  ↓                    │  ↓                       │
│  Detection Validator  │  Operation results       │
└───────────┬───────────┴──────────────────────────┘
            │
            ▼
       Coverage Report
       Matrix: technique × detected/missed
       Gap analysis + recommendations
```

## Portfolio context

| Project | Description |
|---------|-------------|
| [OCSF Transformer](https://github.com/Lamurrz/ocsf-transformer) | Normalize raw vendor logs → OCSF |
| [CyberGraph-AD](https://github.com/Lamurrz/cybergraph-ad) | Detect behavioral anomalies via graph fusion |
| [Meridian KG](https://github.com/Lamurrz/meridian-atlas-attack-kg) | MITRE ATLAS/ATT&CK knowledge graph |
| [Meridian Risk API](https://github.com/Lamurrz/meridian-api) | Assess threat exposure via risk scoring |
| [AI CSF Profiler](https://github.com/Lamurrz/ai-csf-profiler) | Evaluate compliance via NIST CSF 2.0 |
| **Meridian Emulation** | Validate detection coverage via ATT&CK emulation (this project) |

The narrative: **normalize → detect → assess → comply → validate.**

## Quick start

```bash
git clone https://github.com/Lamurrz/meridian-emulation.git
cd meridian-emulation

python -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Show catalog stats and fetch Atomic Red Team index
python run.py --mode catalog --refresh

# Dry-run plan using Meridian control gaps
python run.py --mode plan

# Dry-run with specific techniques
python run.py --mode plan --techniques T1110 T1078 T1021

# Live execution (requires explicit confirmation)
python run.py --mode run --live --confirm
```

## Modes

| Mode | Description |
|------|-------------|
| `catalog` | Show Atomic Red Team cache stats, optionally refresh from GitHub |
| `plan` | Dry-run: generate execution plan without running anything (safe default) |
| `run` | Execute atomic tests; dry-run unless `--live --confirm` provided |
| `full` | Full pipeline: plan or run + validate + report |
| `caldera` | Generate Caldera adversary profile YAML from Meridian gaps (Scope A) |
| `caldera-push` | Push profile to running Caldera instance and optionally launch operation (Scope B) |

## CLI reference

```
python run.py [--mode {plan,run,full,catalog,caldera,caldera-push}]
              [--techniques T1110 T1078 ...]   # specific technique IDs
              [--platform windows|linux|macos]  # filter tests by OS
              [--max-techniques N]              # cap selection (default: 20)
              [--all-techniques]                # include non-AI-relevant techniques
              [--live]                          # enable live execution
              [--confirm]                       # required with --live
              [--validation-window N]           # minutes to look back for findings
              [--output-dir PATH]               # results output directory
              [--refresh]                       # force refresh of atomic catalog
              [--caldera-url URL]               # Caldera server URL (default: http://localhost:8888)
              [--caldera-key KEY]               # Caldera API key
              [--agent-group GROUP]             # Caldera agent group (default: red)
              [--profile-name NAME]             # name for generated adversary profile
              [--write]                         # write profile YAML to disk (caldera mode)
              [--split-by-tactic]               # one profile per tactic (caldera mode)
```

## Caldera integration

### Scope A — Profile generator (no running Caldera required)

Generates Caldera-compatible adversary profile YAMLs from Meridian control gaps.
Profiles can be loaded manually by dropping them into `caldera/data/adversaries/`.

```bash
# Dry-run — show what would be generated
python run.py --mode caldera --techniques T1057 T1082 T1021.002 T1113

# Write YAML to disk
python run.py --mode caldera --techniques T1057 T1082 T1021.002 T1113 \
  --write --output-dir data/caldera_profiles
```

### Scope B — API client (requires running Caldera)

Programmatically pushes profiles to a running Caldera instance and optionally
launches operations against deployed agents.

```bash
# Extract credentials from Docker logs
python caldera_creds.py

# Push profile to Caldera (dry-run — creates profile, no operation launched)
python run.py --mode caldera-push \
  --techniques T1057 T1082 T1021.002 T1113 \
  --caldera-key <api_key>

# Launch operation against agents (requires deployed Sandcat agent)
python run.py --mode caldera-push \
  --techniques T1057 T1082 T1021.002 T1113 \
  --caldera-key <api_key> \
  --live
```

The client discovers real ability IDs from the live Caldera instance rather than
using a static mapping, ensuring generated profiles reference abilities that
actually exist.

### Caldera setup (Docker)

```bash
git clone https://github.com/apache/caldera.git --recursive
cd caldera

# Patch Dockerfile line 83: add || true to skip emu payload failures
# RUN cd /usr/src/app/plugins/emu; ./download_payloads.sh || true

docker build --build-arg VARIANT=slim -t caldera .
docker run -d --name caldera -p 8888:8888 caldera

# Retrieve generated credentials
python caldera_creds.py
```

### Credential management

Caldera generates random credentials on first run. Use `caldera_creds.py` to
retrieve them after any container restart:

```bash
python caldera_creds.py           # print credentials
python caldera_creds.py --save    # save to caldera_creds.json (gitignored)
```

## Technique selection

Techniques are selected in priority order:

1. **Meridian control gaps** — techniques from `/controls/gaps` with no active mitigation
2. **High-risk asset techniques** — techniques targeting assets above a risk threshold
3. **AI-relevant catalog fallback** — if Meridian is unavailable, 91 pre-filtered techniques

Base technique IDs are automatically expanded to subtechniques:
`T1110` → `T1110.001` (Password Guessing), `T1110.003` (Password Spraying), `T1110.004` (Credential Stuffing)

## Atomic Red Team integration

- 697 techniques available across Windows, Linux, and macOS
- 91 pre-filtered as AI/ML infrastructure relevant
- Tests fetched from GitHub and cached locally (24-hour TTL)
- Automatic subtechnique expansion from base technique IDs

## Detection validation

After execution, the validator checks CyberGraph-AD findings for matching anomaly types:

| ATT&CK Technique | Expected CyberGraph-AD Anomaly |
|------------------|-------------------------------|
| T1110 (Brute Force) | `brute_force` |
| T1110.003 (Password Spraying) | `credential_stuffing` |
| T1021 (Remote Services) | `lateral_movement` |
| T1530 (Cloud Storage) | `data_exfiltration` |
| T1078 (Valid Accounts) | `privilege_escalation` |
| T1133 (External Remote Services) | `off_hours_access` |

## Safety

- **Dry-run is the default** for all modes — no execution without explicit flags
- Atomic Red Team: requires both `--live` and `--confirm` to execute
- Caldera: requires `--live` to launch operations; profile creation is always safe
- Cleanup commands run automatically after each atomic test in live mode
- Serial execution only — no concurrent test runs
- Atomic cache, results, and `caldera_creds.json` are gitignored

## Roadmap

- [x] Atomic Red Team integration — plan, execute, validate
- [x] Caldera Scope A — adversary profile YAML generation from Meridian gaps
- [x] Caldera Scope B — programmatic profile push + operation launch via REST API
- [ ] Caldera Scope C — poll operation results → coverage report feedback
- [ ] ATLAS-specific test library — custom atomics for ML attack techniques
- [ ] `pipeline.py` — live OCSF Transformer → CyberGraph-AD ingestion
- [ ] HTML coverage report with ATT&CK Navigator matrix visualization

## Project structure

```
meridian-emulation/
├── caldera/
│   ├── caldera_profile_generator.py  # Scope A: YAML profile generation
│   └── caldera_client.py             # Scope B: REST API client
├── catalog/
│   └── atomic_catalog.py             # Fetch + cache Atomic Red Team YAMLs
├── selector/
│   └── technique_selector.py         # Map Meridian gaps → Atomic test IDs
├── runner/
│   └── emulation_runner.py           # Dry-run + live execution
├── validator/
│   └── detection_validator.py        # Check CyberGraph-AD findings
├── report/
│   └── coverage_report.py            # Coverage matrix + gap report
├── caldera_creds.py                  # Extract Caldera credentials from Docker logs
├── config.py
├── run.py
└── requirements.txt
```
