"""
catalog/atomic_catalog.py
--------------------------
Fetches Atomic Red Team test definitions from the Red Canary GitHub repository
and caches them locally for offline use.

Each "atomic" is a YAML file at:
  https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/{TID}/{TID}.yaml

The index file lists all available technique IDs:
  https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/Indexes/index.yaml

Atomic test YAML structure
--------------------------
attack_technique: T1059.001
display_name: "Command and Scripting Interpreter: PowerShell"
atomic_tests:
  - name: "Mimikatz - Dump Credentials"
    auto_generated_guid: "..."
    description: "..."
    supported_platforms: [windows]
    input_arguments:
      mimikatz_path:
        description: "Path to mimikatz"
        type: Path
        default: "%tmp%\\mimikatz\\x64\\mimikatz.exe"
    executor:
      name: command_prompt | powershell | sh | bash | manual
      command: "..."
      cleanup_command: "..."
    dependencies:
      - description: "..."
        prereq_command: "..."
        get_prereq_command: "..."
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

import requests
import yaml

from config import settings

logger = logging.getLogger("emulation.catalog")

# GitHub raw content base URL
ATOMIC_BASE = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics"
ATOMIC_INDEX = f"{ATOMIC_BASE}/Indexes/index.yaml"


class AtomicCatalog:
    """
    Manages fetching, caching, and querying the Atomic Red Team test library.
    """

    def __init__(self, cache_dir: str = None):
        self._cache_dir = Path(cache_dir or settings.atomic_cache_dir)
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._index: dict[str, Any] = {}
        self._loaded: dict[str, dict] = {}  # technique_id → atomic YAML

    # ── Index management ──────────────────────────────────────────────────────

    def load_index(self, force_refresh: bool = False) -> dict[str, Any]:
        """
        Load the Atomic Red Team index, fetching from GitHub if needed.
        The index maps technique IDs to their YAML file paths.
        """
        index_cache = self._cache_dir / "index.yaml"

        if not force_refresh and self._is_cache_fresh(index_cache):
            logger.info("Loading Atomic index from cache")
            with open(index_cache, encoding="utf-8") as f:
                self._index = yaml.safe_load(f) or {}
            return self._index

        logger.info("Fetching Atomic Red Team index from GitHub...")
        try:
            resp = requests.get(ATOMIC_INDEX, timeout=30)
            resp.raise_for_status()
            with open(index_cache, "w", encoding="utf-8") as f:
                f.write(resp.text)
            self._index = yaml.safe_load(resp.text) or {}
            logger.info(f"Index loaded: {len(self._index)} entries")
        except Exception as exc:
            logger.warning(f"Failed to fetch index: {exc} — using cache if available")
            if index_cache.exists():
                with open(index_cache, encoding="utf-8") as f:
                    self._index = yaml.safe_load(f) or {}

        return self._index

    def available_technique_ids(self) -> list[str]:
        """Return all ATT&CK technique IDs available in the Atomic library."""
        if not self._index:
            self.load_index()
        # Index is organized as tactic -> {technique_id: ...}
        # Flatten all technique IDs across all tactics
        tids = []
        for key, value in self._index.items():
            if isinstance(value, dict):
                # tactic -> technique dict
                tids.extend([k for k in value.keys() if k.startswith("T")])
            elif isinstance(key, str) and key.startswith("T"):
                # flat format: technique_id -> ...
                tids.append(key)
        return list(set(tids))

    # ── Atomic test fetching ──────────────────────────────────────────────────

    def get_atomic(self, technique_id: str, force_refresh: bool = False) -> dict | None:
        """
        Fetch the atomic test YAML for a given ATT&CK technique ID.
        Returns parsed YAML dict or None if not available.

        Example technique IDs: T1059, T1059.001, T1003, T1003.001
        """
        if technique_id in self._loaded and not force_refresh:
            return self._loaded[technique_id]

        cache_path = self._cache_dir / f"{technique_id}.yaml"

        if not force_refresh and self._is_cache_fresh(cache_path):
            try:
                with open(cache_path, encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                self._loaded[technique_id] = data
                return data
            except Exception:
                pass

        # Fetch from GitHub
        url = f"{ATOMIC_BASE}/{technique_id}/{technique_id}.yaml"
        try:
            resp = requests.get(url, timeout=30)
            if resp.status_code == 404:
                logger.debug(f"No atomic tests for {technique_id}")
                return None
            resp.raise_for_status()
            with open(cache_path, "w", encoding="utf-8") as f:
                f.write(resp.text)
            data = yaml.safe_load(resp.text)
            self._loaded[technique_id] = data
            return data
        except Exception as exc:
            logger.warning(f"Failed to fetch atomic for {technique_id}: {exc}")
            return None

    def get_atomics_for_techniques(
        self, technique_ids: list[str], platform: str = None
    ) -> dict[str, dict]:
        """
        Fetch atomics for a list of technique IDs.
        Optionally filter to tests that support a specific platform.

        Returns dict of technique_id → atomic YAML (only those with tests).
        """
        platform = platform or settings.execution_platform
        results = {}

        for tid in technique_ids:
            atomic = self.get_atomic(tid)
            if not atomic:
                continue

            tests = atomic.get("atomic_tests", [])
            if platform:
                tests = [
                    t for t in tests
                    if platform.lower() in [p.lower() for p in t.get("supported_platforms", [])]
                ]

            if tests:
                atomic_copy = dict(atomic)
                atomic_copy["atomic_tests"] = tests
                results[tid] = atomic_copy
                logger.debug(f"{tid}: {len(tests)} tests on {platform}")

        logger.info(f"Found {len(results)} techniques with atomic tests "
                    f"({len(technique_ids) - len(results)} have no tests on {platform})")
        return results

    # ── Technique metadata ────────────────────────────────────────────────────

    def technique_summary(self, technique_id: str) -> dict | None:
        """Return a summary of available atomic tests for a technique."""
        atomic = self.get_atomic(technique_id)
        if not atomic:
            return None

        tests = atomic.get("atomic_tests", [])
        platforms = set()
        executors = set()
        for t in tests:
            platforms.update(t.get("supported_platforms", []))
            executors.add(t.get("executor", {}).get("name", "unknown"))

        return {
            "technique_id": technique_id,
            "display_name": atomic.get("display_name", ""),
            "test_count": len(tests),
            "platforms": sorted(platforms),
            "executors": sorted(executors),
            "test_names": [t.get("name", "") for t in tests],
        }

    def filter_by_ai_relevance(self, technique_ids: list[str]) -> list[str]:
        """
        Filter technique IDs to those most relevant to AI/ML infrastructure.
        Based on MITRE ATT&CK techniques that appear in Meridian's TARGETS rules.
        """
        # ATT&CK techniques commonly mapped to AI/ML asset attacks
        AI_RELEVANT_PREFIXES = {
            "T1190",  # Exploit Public-Facing Application (InferenceAPI)
            "T1133",  # External Remote Services
            "T1078",  # Valid Accounts (credential attacks)
            "T1110",  # Brute Force
            "T1552",  # Unsecured Credentials
            "T1530",  # Data from Cloud Storage
            "T1537",  # Transfer Data to Cloud Account
            "T1567",  # Exfiltration Over Web Service
            "T1059",  # Command and Scripting Interpreter
            "T1055",  # Process Injection
            "T1003",  # OS Credential Dumping
            "T1021",  # Remote Services (lateral movement)
            "T1083",  # File and Directory Discovery
            "T1082",  # System Information Discovery
            "T1057",  # Process Discovery
            "T1012",  # Query Registry
            "T1518",  # Software Discovery
            "T1071",  # Application Layer Protocol (C2)
            "T1105",  # Ingress Tool Transfer
            "T1560",  # Archive Collected Data
        }
        return [
            tid for tid in technique_ids
            if any(tid.startswith(prefix) for prefix in AI_RELEVANT_PREFIXES)
        ]

    # ── Cache helpers ─────────────────────────────────────────────────────────

    def _is_cache_fresh(self, path: Path) -> bool:
        """Return True if the cached file exists and is within the TTL."""
        if not path.exists():
            return False
        age_hours = (time.time() - path.stat().st_mtime) / 3600
        return age_hours < settings.atomic_cache_ttl_hours

    def cache_stats(self) -> dict:
        """Return stats about the local cache."""
        cached = list(self._cache_dir.glob("T*.yaml"))
        return {
            "cached_techniques": len(cached),
            "cache_dir": str(self._cache_dir),
            "index_cached": (self._cache_dir / "index.yaml").exists(),
        }
