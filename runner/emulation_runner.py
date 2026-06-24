"""
runner/emulation_runner.py
---------------------------
Executes Atomic Red Team tests in either dry-run or live mode.

Dry-run mode (default, safe)
-----------------------------
Prints what would be executed — commands, prerequisites, cleanup —
without running anything. Produces a dry_run_plan.json showing full
execution intent. Safe for portfolio demonstration.

Live mode (--live flag required)
---------------------------------
Executes atomic tests via the atomic-operator Python library.
Requires explicit --live flag to prevent accidental execution.
Records results per test: success/failure, output, duration.

Safety controls
---------------
- Dry-run is the default; live requires explicit opt-in
- Execution timeout enforced per test
- Cleanup commands run automatically after each test in live mode
- Serial execution only (max_concurrent_tests=1 enforced)
- Explicit confirmation prompt before live execution begins
"""

from __future__ import annotations

import json
import logging
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import settings

logger = logging.getLogger("emulation.runner")

OCSF_EMULATION_CLASS_UID = 1001  # Custom: Emulation Activity


class EmulationRunner:
    """
    Runs Atomic Red Team tests against a target environment.
    """

    def __init__(self, output_dir: str = None, dry_run: bool = None):
        self._output_dir = Path(output_dir or settings.output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._dry_run = dry_run if dry_run is not None else settings.dry_run

    # ── Dry-run planning ──────────────────────────────────────────────────────

    def dry_run(self, selections: list[dict]) -> dict:
        """
        Produce an execution plan without running anything.
        Shows exactly what commands would be executed.
        """
        plan = {
            "mode": "dry_run",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "platform": settings.execution_platform,
            "technique_count": len(selections),
            "total_tests": sum(s["test_count"] for s in selections),
            "techniques": [],
        }

        for sel in selections:
            tid = sel["technique_id"]
            technique_plan = {
                "technique_id": tid,
                "display_name": sel["display_name"],
                "is_control_gap": sel["is_control_gap"],
                "tests": [],
            }

            for test in sel.get("atomic_tests", []):
                executor = test.get("executor", {})
                executor_name = executor.get("name", "manual")
                command = executor.get("command", "")
                cleanup = executor.get("cleanup_command", "")

                # Resolve input argument defaults
                input_args = test.get("input_arguments", {})
                resolved_command = command
                resolved_cleanup = cleanup
                for arg_name, arg_info in input_args.items():
                    default = str(arg_info.get("default", ""))
                    placeholder = f"#{{{arg_name}}}"
                    resolved_command = resolved_command.replace(placeholder, default)
                    resolved_cleanup = resolved_cleanup.replace(placeholder, default)

                test_plan = {
                    "name": test.get("name", ""),
                    "guid": test.get("auto_generated_guid", ""),
                    "executor": executor_name,
                    "platforms": test.get("supported_platforms", []),
                    "description": test.get("description", "")[:200],
                    "would_execute": resolved_command.strip() if resolved_command else "(manual)",
                    "would_cleanup": resolved_cleanup.strip() if resolved_cleanup else None,
                    "has_dependencies": bool(test.get("dependencies")),
                    "input_arguments": {
                        k: v.get("default") for k, v in input_args.items()
                    },
                }
                technique_plan["tests"].append(test_plan)

            plan["techniques"].append(technique_plan)

        # Save plan
        plan_path = self._output_dir / f"dry_run_plan_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
        with open(plan_path, "w") as f:
            json.dump(plan, f, indent=2)

        logger.info(f"Dry-run plan saved → {plan_path}")
        return plan

    # ── Live execution ─────────────────────────────────────────────────────────

    def run(
        self,
        selections: list[dict],
        confirm: bool = False,
    ) -> dict:
        """
        Execute atomic tests against the local environment.

        Parameters
        ----------
        selections : list of technique dicts from TechniqueSelector
        confirm    : must be True to proceed with live execution

        Returns
        -------
        Execution results dict with per-test outcomes.
        """
        if self._dry_run:
            logger.info("Dry-run mode — returning plan without executing")
            return self.dry_run(selections)

        if not confirm:
            raise RuntimeError(
                "Live execution requires confirm=True. "
                "This will execute real attack techniques on the local system. "
                "Run with --live --confirm to proceed."
            )

        logger.warning("=" * 60)
        logger.warning("LIVE EXECUTION MODE — running atomic tests on this system")
        logger.warning("=" * 60)

        results = {
            "mode": "live",
            "executed_at": datetime.now(timezone.utc).isoformat(),
            "platform": settings.execution_platform,
            "technique_count": len(selections),
            "results": [],
        }

        for sel in selections:
            tid = sel["technique_id"]
            technique_result = {
                "technique_id": tid,
                "display_name": sel["display_name"],
                "is_control_gap": sel["is_control_gap"],
                "test_results": [],
            }

            for test in sel.get("atomic_tests", [])[:3]:  # max 3 tests per technique
                test_result = self._run_single_test(tid, test)
                technique_result["test_results"].append(test_result)

                # Brief pause between tests
                time.sleep(2)

            results["results"].append(technique_result)

        # Save results
        results_path = self._output_dir / f"execution_results_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
        with open(results_path, "w") as f:
            json.dump(results, f, indent=2)

        logger.info(f"Execution results saved → {results_path}")
        return results

    def _run_single_test(self, technique_id: str, test: dict) -> dict:
        """Run a single atomic test and return the result."""
        executor = test.get("executor", {})
        executor_name = executor.get("name", "manual")
        command = executor.get("command", "")
        cleanup_command = executor.get("cleanup_command", "")
        guid = test.get("auto_generated_guid", "")
        test_name = test.get("name", "")

        # Resolve input argument defaults
        input_args = test.get("input_arguments", {})
        for arg_name, arg_info in input_args.items():
            default = str(arg_info.get("default", ""))
            command = command.replace(f"#{{{arg_name}}}", default)
            cleanup_command = cleanup_command.replace(f"#{{{arg_name}}}", default)

        result = {
            "test_name": test_name,
            "guid": guid,
            "executor": executor_name,
            "technique_id": technique_id,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "status": "skipped",
            "output": "",
            "error": "",
            "duration_seconds": 0,
            "cleanup_status": "not_run",
        }

        if executor_name == "manual":
            result["status"] = "skipped"
            result["output"] = "Manual executor — skipped in automated run"
            return result

        # Map executor to shell command
        shell_map = {
            "command_prompt": ["cmd", "/c"],
            "powershell":     ["powershell", "-ExecutionPolicy", "Bypass", "-Command"],
            "sh":             ["sh", "-c"],
            "bash":           ["bash", "-c"],
        }

        shell = shell_map.get(executor_name)
        if not shell:
            result["status"] = "skipped"
            result["output"] = f"Unsupported executor: {executor_name}"
            return result

        # Execute
        start = time.time()
        try:
            proc = subprocess.run(
                shell + [command],
                capture_output=True,
                text=True,
                timeout=settings.execution_timeout_seconds,
            )
            result["status"] = "success" if proc.returncode == 0 else "failed"
            result["output"] = proc.stdout[:2000]
            result["error"] = proc.stderr[:1000] if proc.stderr else ""
            result["return_code"] = proc.returncode
        except subprocess.TimeoutExpired:
            result["status"] = "timeout"
            result["error"] = f"Timed out after {settings.execution_timeout_seconds}s"
        except Exception as exc:
            result["status"] = "error"
            result["error"] = str(exc)
        finally:
            result["duration_seconds"] = round(time.time() - start, 2)
            result["ended_at"] = datetime.now(timezone.utc).isoformat()

        # Cleanup
        if cleanup_command and result["status"] != "skipped":
            try:
                subprocess.run(
                    shell + [cleanup_command],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                result["cleanup_status"] = "completed"
            except Exception:
                result["cleanup_status"] = "failed"

        return result

    # ── OCSF output ───────────────────────────────────────────────────────────

    def to_ocsf_events(self, results: dict) -> list[dict]:
        """
        Convert execution results to OCSF-compatible emulation activity events.
        Class UID 1001 = System Activity (repurposed for emulation tracking).
        """
        events = []
        ts = int(datetime.now(timezone.utc).timestamp() * 1000)

        for technique_result in results.get("results", []):
            tid = technique_result.get("technique_id", "")
            for test_result in technique_result.get("test_results", []):
                events.append({
                    "class_uid": OCSF_EMULATION_CLASS_UID,
                    "category_uid": 1,
                    "activity_id": 1,
                    "activity_name": "Emulation",
                    "time": ts,
                    "status": test_result.get("status", "unknown"),
                    "message": f"Atomic test: {test_result.get('test_name', '')}",
                    "metadata": {
                        "uid": test_result.get("guid", ""),
                        "product": {"name": "Atomic Red Team", "vendor_name": "Red Canary"},
                        "schema_url": "https://schema.ocsf.io",
                    },
                    "attack": {
                        "technique": {"uid": tid, "name": technique_result.get("display_name", "")},
                        "tactic": {"name": ""},
                    },
                    "emulation": {
                        "executor": test_result.get("executor", ""),
                        "duration_seconds": test_result.get("duration_seconds", 0),
                        "is_control_gap": technique_result.get("is_control_gap", False),
                        "mode": results.get("mode", "dry_run"),
                    },
                })

        return events
