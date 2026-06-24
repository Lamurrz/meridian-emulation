"""
report/coverage_report.py
--------------------------
Generates a detection coverage matrix and gap report from emulation
and validation results.

Output formats
--------------
JSON: structured coverage data for downstream consumption
Console: rich terminal table (uses rich library)

Coverage matrix structure
--------------------------
Rows:    ATT&CK techniques
Columns: Detection status (detected / missed / not_executed / would_test)
         Control gap status (gap / mitigated)
         Anomaly type mapping
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("emulation.report")


class CoverageReporter:
    """
    Generates detection coverage reports from emulation and validation results.
    """

    def __init__(self, output_dir: str = "data/results"):
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        execution_results: dict,
        validation_results: dict,
        selection_summary: dict,
    ) -> dict:
        """
        Generate a comprehensive coverage report.

        Parameters
        ----------
        execution_results  : from EmulationRunner.run() or .dry_run()
        validation_results : from DetectionValidator.validate()
        selection_summary  : from TechniqueSelector.selection_summary()

        Returns
        -------
        Coverage report dict (also saved to output_dir).
        """
        mode = execution_results.get("mode", "dry_run")
        is_dry_run = mode == "dry_run"

        # Build technique map
        technique_coverage = validation_results.get("technique_coverage", [])
        gap_count = sum(1 for t in technique_coverage if t.get("is_control_gap"))

        # Coverage statistics
        summary = validation_results.get("summary", {})
        total = summary.get("total_techniques", 0)
        detected = summary.get("detected", 0)
        missed = summary.get("missed", 0)
        would_test = summary.get("would_test", 0)

        detection_rate = summary.get("detection_rate")
        gap_detection_rate = None
        if not is_dry_run and total > 0:
            gap_techniques = [t for t in technique_coverage if t.get("is_control_gap")]
            gap_detected = sum(1 for t in gap_techniques if t.get("detected"))
            gap_detection_rate = gap_detected / len(gap_techniques) if gap_techniques else None

        report = {
            "report_id": f"coverage-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": mode,
            "platform": execution_results.get("platform", "unknown"),

            "executive_summary": {
                "total_techniques_selected": selection_summary.get("total_techniques", 0),
                "control_gap_techniques": gap_count,
                "total_atomic_tests": selection_summary.get("total_atomic_tests", 0),
                "detection_rate": detection_rate,
                "gap_detection_rate": gap_detection_rate,
                "mode_note": (
                    "Dry-run mode: shows what would be tested, no execution occurred."
                    if is_dry_run else
                    "Live mode: actual test execution results."
                ),
            },

            "coverage_matrix": self._build_matrix(technique_coverage),
            "gap_analysis": self._build_gap_analysis(technique_coverage),
            "recommendations": self._build_recommendations(technique_coverage, is_dry_run),
            "raw_validation": validation_results,
        }

        # Save JSON
        report_path = self._output_dir / f"{report['report_id']}.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)
        logger.info(f"Coverage report saved → {report_path}")

        # Print console summary
        self._print_summary(report)

        return report

    def _build_matrix(self, technique_coverage: list[dict]) -> list[dict]:
        """Build the coverage matrix rows."""
        matrix = []
        for t in technique_coverage:
            status = t.get("detection_status", "unknown")
            matrix.append({
                "technique_id": t.get("technique_id", ""),
                "technique_name": t.get("display_name", ""),
                "is_control_gap": t.get("is_control_gap", False),
                "expected_anomaly": t.get("expected_anomaly_type", "unknown"),
                "status": status,
                "detected": t.get("detected"),
                "finding_count": len(t.get("matching_findings", [])),
            })
        # Sort: gaps first, then by status
        matrix.sort(key=lambda x: (not x["is_control_gap"], x["status"]))
        return matrix

    def _build_gap_analysis(self, technique_coverage: list[dict]) -> dict:
        """Identify detection gaps — techniques executed but not detected."""
        missed = [
            t for t in technique_coverage
            if t.get("detection_status") == "missed"
        ]
        gap_missed = [t for t in missed if t.get("is_control_gap")]

        return {
            "total_missed": len(missed),
            "control_gap_missed": len(gap_missed),
            "missed_techniques": [
                {
                    "technique_id": t.get("technique_id"),
                    "name": t.get("display_name"),
                    "is_control_gap": t.get("is_control_gap"),
                    "expected_anomaly": t.get("expected_anomaly_type"),
                    "priority": "CRITICAL" if t.get("is_control_gap") else "HIGH",
                }
                for t in missed
            ],
        }

    def _build_recommendations(
        self, technique_coverage: list[dict], is_dry_run: bool
    ) -> list[dict]:
        """Generate prioritized remediation recommendations."""
        recs = []

        if is_dry_run:
            recs.append({
                "priority": "INFO",
                "recommendation": "Run in live mode (--live --confirm) to validate actual detection coverage",
                "rationale": "Dry-run shows what would be tested but cannot validate CyberGraph-AD detection",
            })

        # Control gaps with no anomaly mapping = detection blind spots
        unmapped_gaps = [
            t for t in technique_coverage
            if t.get("is_control_gap") and not t.get("expected_anomaly_type")
        ]
        if unmapped_gaps:
            recs.append({
                "priority": "HIGH",
                "recommendation": "Extend CyberGraph-AD anomaly type coverage",
                "techniques": [t["technique_id"] for t in unmapped_gaps],
                "rationale": (
                    f"{len(unmapped_gaps)} control gap techniques have no corresponding "
                    "CyberGraph-AD anomaly type — these cannot be detected by the current model"
                ),
            })

        # Missed control gap techniques = critical detection gaps
        missed_gaps = [
            t for t in technique_coverage
            if t.get("detection_status") == "missed" and t.get("is_control_gap")
        ]
        if missed_gaps:
            recs.append({
                "priority": "CRITICAL",
                "recommendation": "Tune CyberGraph-AD detection thresholds for missed control gap techniques",
                "techniques": [t["technique_id"] for t in missed_gaps],
                "rationale": (
                    f"{len(missed_gaps)} techniques have no mitigation control AND were not "
                    "detected by CyberGraph-AD — these represent unmitigated blind spots"
                ),
            })

        # Add Meridian control creation recommendation for missed gaps
        if missed_gaps:
            recs.append({
                "priority": "HIGH",
                "recommendation": "Create mitigation controls in Meridian for undetected techniques",
                "techniques": [t["technique_id"] for t in missed_gaps],
                "rationale": "If detection cannot be improved, compensating controls should be implemented",
            })

        return recs

    def _print_summary(self, report: dict) -> None:
        """Print a clean summary to the console."""
        summary = report.get("executive_summary", {})
        mode = report.get("mode", "unknown")
        matrix = report.get("coverage_matrix", [])

        print(f"\n{'='*60}")
        print(f"  Emulation Coverage Report — {mode.upper()}")
        print(f"{'='*60}")
        print(f"  Techniques selected:  {summary.get('total_techniques_selected', 0)}")
        print(f"  Control gap techs:    {summary.get('control_gap_techniques', 0)}")
        print(f"  Total atomic tests:   {summary.get('total_atomic_tests', 0)}")

        dr = summary.get("detection_rate")
        if dr is not None:
            print(f"  Detection rate:       {dr:.1%}")
        gdr = summary.get("gap_detection_rate")
        if gdr is not None:
            print(f"  Gap detection rate:   {gdr:.1%}")

        print(f"\n  Coverage matrix ({len(matrix)} techniques):")
        status_counts = {}
        for row in matrix:
            s = row.get("status", "unknown")
            status_counts[s] = status_counts.get(s, 0) + 1
        for status, count in sorted(status_counts.items()):
            marker = {"detected": "✓", "missed": "✗", "would_test": "→", "not_executed": "—"}.get(status, "?")
            print(f"    {marker} {status}: {count}")

        recs = report.get("recommendations", [])
        if recs:
            print(f"\n  Recommendations ({len(recs)}):")
            for rec in recs:
                print(f"    [{rec.get('priority','?')}] {rec.get('recommendation','')}")

        print(f"\n  Report ID: {report.get('report_id')}")
        print(f"{'='*60}\n")
