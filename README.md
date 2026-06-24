# Meridian Emulation

ATT&CK technique emulation and detection validation pipeline, integrating the
[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) library with
the Meridian Risk Scoring API and CyberGraph-AD for closed-loop purple team validation.

## What it does

**Meridian Emulation** closes the loop in the AI security engineering pipeline by
answering: *do your detections actually fire against the techniques your threat
intelligence says you're exposed to?*

```
Meridian /controls/gaps
        │  Techniques with no active mitigation
        ▼
Technique Selector
        │  Maps gap techniques → Atomic Red Team tests
        │  Expands base IDs to subtechniques (T1110 → T1110.001, .003, .004)
        ▼
Emulation Runner
        │  Dry-run: execution plan with resolved commands
        │  Live:    subprocess execution with cleanup
        ▼
Detection Validator
        │  Checks CyberGraph-AD findings for matching anomaly types
        ▼
Coverage Report
        │  Matrix: technique × detected/missed
        │  Gap analysis: undetected control gap techniques
        └─ Recommendations: threshold tuning + Meridian control creation
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

## CLI reference

```
python run.py [--mode {plan,run,full,catalog}]
              [--techniques T1110 T1078 ...]   # specific technique IDs
              [--platform windows|linux|macos]  # filter atomic tests by OS
              [--max-techniques N]              # cap selection (default: 20)
              [--all-techniques]                # include non-AI-relevant techniques
              [--live]                          # enable live execution
              [--confirm]                       # required with --live
              [--validation-window N]           # minutes to look back for findings
              [--output-dir PATH]               # results output directory
              [--refresh]                       # force refresh of atomic catalog
```

## Technique selection

Techniques are selected in priority order:

1. **Meridian control gaps** — techniques from `/controls/gaps` with no active mitigation
2. **High-risk asset techniques** — techniques targeting assets above a risk threshold
3. **AI-relevant catalog fallback** — if Meridian is unavailable, 91 pre-filtered techniques

Base technique IDs are automatically expanded to subtechniques:
`T1110` → `T1110.001` (Password Guessing), `T1110.003` (Password Spraying), `T1110.004` (Credential Stuffing)

## Atomic Red Team integration

Atomic Red Team is a library of tests mapped to the MITRE ATT&CK framework that security teams can use to quickly, portably, and reproducibly test their environments.

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

## Coverage report

The report includes:

- **Coverage matrix** — each technique with detected/missed/would_test status
- **Gap analysis** — techniques executed but not detected, prioritized by control gap status
- **Recommendations** — threshold tuning targets, Meridian control creation suggestions

```json
{
  "executive_summary": {
    "total_techniques_selected": 20,
    "control_gap_techniques": 5,
    "total_atomic_tests": 196,
    "detection_rate": 0.6,
    "gap_detection_rate": 0.4
  },
  "gap_analysis": {
    "missed_techniques": [
      {
        "technique_id": "T1110.003",
        "priority": "CRITICAL",
        "is_control_gap": true
      }
    ]
  }
}
```

## Safety

- **Dry-run is the default** — no execution without explicit `--live` flag
- Live execution requires both `--live` and `--confirm` to prevent accidents
- Cleanup commands run automatically after each test in live mode
- Serial execution only — no concurrent test runs
- Atomic cache and results are gitignored

## Roadmap

- [ ] ATLAS-specific test library — custom atomics for ML attack techniques not covered by Atomic Red Team (model extraction probes, adversarial input generation, prompt injection patterns)
- [ ] Caldera integration — adversary profile generation from Meridian control gaps
- [ ] Meridian risk score feedback — update asset risk scores based on detection outcomes
- [ ] HTML coverage report with ATT&CK Navigator matrix visualization

## Project structure

```
meridian-emulation/
├── catalog/
│   └── atomic_catalog.py      # Fetch + cache Atomic Red Team YAMLs
├── selector/
│   └── technique_selector.py  # Map Meridian gaps → Atomic test IDs
├── runner/
│   └── emulation_runner.py    # Dry-run + live execution
├── validator/
│   └── detection_validator.py # Check CyberGraph-AD findings
├── report/
│   └── coverage_report.py     # Coverage matrix + gap report
├── config.py
├── run.py
└── requirements.txt
```
