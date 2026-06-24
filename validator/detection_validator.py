"""
validator/detection_validator.py
----------------------------------
Validates whether CyberGraph-AD detected the techniques that were
emulated by the emulation runner.

Two modes
---------
1. API mode: queries CyberGraph-AD's findings API for recent detections
2. File mode: reads from the findings JSON files in data/findings/

Matching logic
--------------
Each atomic test execution creates a time window (start → start + 5min).
We look for OCSF Detection Finding events in that window where the
anomaly type matches the technique category.

ATT&CK technique → anomaly type mapping
-----------------------------------------
T1110 (Brute Force)          → brute_force
T1078 (Valid Accounts)       → credential_stuffing
T1021 (Remote Services)      → lateral_movement
T1530 (Cloud Storage Access) → data_exfiltration
T1078 (Privileged Account)   → privilege_escalation
Others at off-hours           → off_hours_access
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

import httpx

from config import settings

logger = logging.getLogger("emulation.validator")

# ATT&CK technique → CyberGraph-AD anomaly type mapping
TECHNIQUE_TO_ANOMALY: dict[str, str] = {
    "T1110": "brute_force",
    "T1110.001": "brute_force",
    "T1110.003": "credential_stuffing",
    "T1110.004": "credential_stuffing",
    "T1078": "privilege_escalation",
    "T1078.002": "privilege_escalation",
    "T1021": "lateral_movement",
    "T1021.001": "lateral_movement",
    "T1021.002": "lateral_movement",
    "T1530": "data_exfiltration",
    "T1537": "data_exfiltration",
    "T1567": "data_exfiltration",
    "T1552": "credential_stuffing",
    "T1552.001": "credential_stuffing",
    "T1133": "off_hours_access",
    "T1190": "privilege_escalation",
}


class DetectionValidator:
    """
    Validates detection coverage by checking whether CyberGraph-AD
    fired findings for the emulated techniques.
    """

    def __init__(self):
        self._cybergraph_url = settings.cybergraph_api_url
        self._findings_dir = Path(settings.cybergraph_findings_dir) if settings.cybergraph_findings_dir else None

    # ── Finding retrieval ─────────────────────────────────────────────────────

    def get_recent_findings(self, since_minutes: int = 30) -> list[dict]:
        """
        Retrieve recent OCSF Detection Finding events from CyberGraph-AD.
        Tries API first, falls back to file system.
        """
        # Try API
        if self._cybergraph_url:
            try:
                resp = httpx.get(
                    f"{self._cybergraph_url}/findings/recent",
                    params={"minutes": since_minutes},
                    timeout=10,
                )
                resp.raise_for_status()
                findings = resp.json()
                logger.info(f"Retrieved {len(findings)} findings from CyberGraph-AD API")
                return findings
            except Exception as exc:
                logger.warning(f"CyberGraph-AD API unavailable ({exc}) — trying file system")

        # Try file system
        if self._findings_dir and self._findings_dir.exists():
            return self._load_findings_from_files(since_minutes)

        logger.warning("No CyberGraph-AD source available — validation will show all as undetected")
        return []

    def _load_findings_from_files(self, since_minutes: int) -> list[dict]:
        """Load findings from JSON files in the CyberGraph-AD findings directory."""
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=since_minutes)
        cutoff_ms = int(cutoff.timestamp() * 1000)

        findings = []
        for f in sorted(self._findings_dir.glob("findings_*.json")):
            try:
                with open(f) as fh:
                    data = json.load(fh)
                    if isinstance(data, list):
                        for finding in data:
                            if finding.get("time", 0) >= cutoff_ms:
                                findings.append(finding)
                    elif isinstance(data, dict) and data.get("time", 0) >= cutoff_ms:
                        findings.append(data)
            except Exception as exc:
                logger.debug(f"Could not read {f}: {exc}")

        logger.info(f"Loaded {len(findings)} findings from files")
        return findings

    # ── Validation logic ──────────────────────────────────────────────────────

    def validate(
        self,
        execution_results: dict,
        since_minutes: int = 30,
    ) -> dict:
        """
        Validate detection coverage for emulated techniques.

        Returns a coverage report showing which techniques were detected,
        which were missed, and the overall detection rate.
        """
        findings = self.get_recent_findings(since_minutes)
        is_dry_run = execution_results.get("mode") == "dry_run"

        # Build set of detected anomaly types from findings
        detected_anomaly_types = set()
        for finding in findings:
            anomaly_type = finding.get("unmapped", {}).get("anomaly_type", "")
            if anomaly_type and anomaly_type != "none":
                detected_anomaly_types.add(anomaly_type)

        coverage_results = []
        total_techniques = 0
        detected_count = 0

        for technique_result in execution_results.get("results", []):
            tid = technique_result.get("technique_id", "")
            # Also check base technique (T1110.001 → T1110)
            base_tid = tid.split(".")[0]

            expected_anomaly = (
                TECHNIQUE_TO_ANOMALY.get(tid) or
                TECHNIQUE_TO_ANOMALY.get(base_tid)
            )

            # For dry-run: mark as "would_test" rather than detected/missed
            if is_dry_run:
                detection_status = "would_test"
                detected = None
            else:
                test_results = technique_result.get("test_results", [])
                any_executed = any(
                    r.get("status") in ("success", "failed")
                    for r in test_results
                )

                if not any_executed:
                    detection_status = "not_executed"
                    detected = None
                elif expected_anomaly and expected_anomaly in detected_anomaly_types:
                    detection_status = "detected"
                    detected = True
                    detected_count += 1
                else:
                    detection_status = "missed"
                    detected = False

                total_techniques += 1

            coverage_results.append({
                "technique_id": tid,
                "display_name": technique_result.get("display_name", ""),
                "is_control_gap": technique_result.get("is_control_gap", False),
                "expected_anomaly_type": expected_anomaly,
                "detection_status": detection_status,
                "detected": detected,
                "matching_findings": [
                    f for f in findings
                    if f.get("unmapped", {}).get("anomaly_type") == expected_anomaly
                ] if expected_anomaly else [],
            })

        detection_rate = (
            detected_count / total_techniques
            if total_techniques > 0 else None
        )

        return {
            "validation_mode": "dry_run_preview" if is_dry_run else "live",
            "validated_at": datetime.now(timezone.utc).isoformat(),
            "since_minutes": since_minutes,
            "total_findings": len(findings),
            "detected_anomaly_types": sorted(detected_anomaly_types),
            "technique_coverage": coverage_results,
            "summary": {
                "total_techniques": total_techniques,
                "detected": detected_count,
                "missed": total_techniques - detected_count,
                "not_executed": sum(
                    1 for r in coverage_results if r["detection_status"] == "not_executed"
                ),
                "would_test": sum(
                    1 for r in coverage_results if r["detection_status"] == "would_test"
                ),
                "detection_rate": detection_rate,
            },
        }
