"""
caldera/caldera_client.py
--------------------------
Scope B: Caldera REST API client.

Programmatically creates adversary profiles, launches operations,
and retrieves results via the Caldera v2 REST API.

This builds on Scope A (caldera_profile_generator.py) by pushing
generated profiles directly into a running Caldera instance rather
than requiring manual file copy.

Usage
-----
  from caldera.caldera_client import CalderaClient

  client = CalderaClient(url="http://localhost:8888", api_key="ADMIN123")

  # Verify connection
  abilities = client.list_abilities()
  print(f"Connected — {len(abilities)} abilities available")

  # Push an adversary profile
  profile_id = client.create_adversary(
      name="Meridian Gap Profile",
      description="Auto-generated from control gaps",
      ability_ids=["4d9b079c", "29451844", "665432a4"],
  )

  # List agents
  agents = client.list_agents()

  # Launch operation
  op_id = client.create_operation(
      name="Gap Validation Run",
      adversary_id=profile_id,
      agent_group="red",
  )

  # Poll for results
  results = client.poll_operation(op_id)
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any

import httpx

logger = logging.getLogger("emulation.caldera_client")


class CalderaClient:
    """
    REST API client for a running Caldera instance.
    Handles adversary profile management, operation lifecycle,
    and result retrieval.
    """

    def __init__(
        self,
        url: str = "http://localhost:8888",
        api_key: str = "ADMIN123",
        timeout: int = 30,
    ):
        self._url = url.rstrip("/")
        self._headers = {
            "KEY": api_key,
            "Content-Type": "application/json",
        }
        self._timeout = timeout

    # ── Connection check ──────────────────────────────────────────────────────

    def health_check(self) -> dict:
        """Verify Caldera is reachable and API key is valid."""
        try:
            abilities = self.list_abilities()
            return {
                "status": "ok",
                "url": self._url,
                "abilities_count": len(abilities),
            }
        except httpx.HTTPStatusError as exc:
            return {
                "status": "auth_error",
                "http_status": exc.response.status_code,
                "message": str(exc),
            }
        except Exception as exc:
            return {
                "status": "unreachable",
                "message": str(exc),
            }

    # ── Abilities ─────────────────────────────────────────────────────────────

    def list_abilities(self, technique_id: str | None = None) -> list[dict]:
        """
        List all abilities in the Caldera instance.
        Optionally filter by ATT&CK technique ID.
        """
        resp = self._get("/api/v2/abilities")
        abilities = resp if isinstance(resp, list) else []

        if technique_id:
            abilities = [
                a for a in abilities
                if a.get("technique_id", "").startswith(technique_id)
            ]

        return abilities

    def get_ability(self, ability_id: str) -> dict | None:
        """Get a specific ability by ID."""
        try:
            return self._get(f"/api/v2/abilities/{ability_id}")
        except Exception:
            return None

    def find_abilities_for_techniques(
        self, technique_ids: list[str], platform: str = "windows"
    ) -> dict[str, list[dict]]:
        """
        Find Caldera abilities matching a list of ATT&CK technique IDs.
        Returns dict: technique_id → list of matching abilities.
        """
        all_abilities = self.list_abilities()
        result: dict[str, list[dict]] = {tid: [] for tid in technique_ids}

        for ability in all_abilities:
            tid = ability.get("technique_id", "")
            if not tid:
                continue

            # Check if this ability matches any of our technique IDs
            for target_tid in technique_ids:
                if tid == target_tid or tid.startswith(target_tid + "."):
                    # Filter by platform
                    executors = ability.get("executors", [])
                    has_platform = any(
                        e.get("platform", "").lower() == platform.lower()
                        for e in executors
                    )
                    if has_platform or not executors:
                        result[target_tid].append(ability)
                    break

        return result

    # ── Adversaries ───────────────────────────────────────────────────────────

    def list_adversaries(self) -> list[dict]:
        """List all adversary profiles."""
        resp = self._get("/api/v2/adversaries")
        return resp if isinstance(resp, list) else []

    def get_adversary(self, adversary_id: str) -> dict | None:
        """Get a specific adversary profile by ID."""
        try:
            return self._get(f"/api/v2/adversaries/{adversary_id}")
        except Exception:
            return None

    def create_adversary(
        self,
        name: str,
        ability_ids: list[str],
        description: str = "",
        adversary_id: str | None = None,
    ) -> str:
        """
        Create a new adversary profile in Caldera.
        Returns the adversary ID.
        """
        profile_id = adversary_id or str(uuid.uuid4())

        payload = {
            "adversary_id": profile_id,
            "name": name,
            "description": description,
            "atomic_ordering": ability_ids,
            "objective": "495a9828-cab1-44dd-a0ca-66e58177d8cc",
        }

        self._post("/api/v2/adversaries", payload)
        logger.info(f"Created adversary profile: {name} ({profile_id})")
        return profile_id

    def delete_adversary(self, adversary_id: str) -> bool:
        """Delete an adversary profile."""
        try:
            self._delete(f"/api/v2/adversaries/{adversary_id}")
            return True
        except Exception:
            return False

    # ── Agents ────────────────────────────────────────────────────────────────

    def list_agents(self) -> list[dict]:
        """List all connected agents."""
        resp = self._get("/api/v2/agents")
        return resp if isinstance(resp, list) else []

    def get_agent_groups(self) -> list[str]:
        """Return list of unique agent groups."""
        agents = self.list_agents()
        return list({a.get("group", "red") for a in agents})

    # ── Operations ────────────────────────────────────────────────────────────

    def list_operations(self) -> list[dict]:
        """List all operations."""
        resp = self._get("/api/v2/operations")
        return resp if isinstance(resp, list) else []

    def create_operation(
        self,
        name: str,
        adversary_id: str,
        agent_group: str = "red",
        planner: str = "atomic",
        fact_source: str = "basic",
        auto_close: bool = True,
        jitter: str = "2/8",
    ) -> str:
        """
        Create and start a new operation.
        Returns the operation ID.
        """
        op_id = str(uuid.uuid4())

        payload = {
            "id": op_id,
            "name": name,
            "adversary": {"adversary_id": adversary_id},
            "group": agent_group,
            "planner": {"id": planner},
            "source": {"id": fact_source},
            "auto_close": auto_close,
            "jitter": jitter,
            "state": "running",
        }

        self._post("/api/v2/operations", payload)
        logger.info(f"Started operation: {name} ({op_id})")
        return op_id

    def get_operation(self, operation_id: str) -> dict | None:
        """Get operation status and details."""
        try:
            return self._get(f"/api/v2/operations/{operation_id}")
        except Exception:
            return None

    def poll_operation(
        self,
        operation_id: str,
        poll_interval: int = 10,
        timeout: int = 600,
    ) -> dict:
        """
        Poll an operation until complete or timeout.

        Returns operation result dict with:
          - status: finished/timeout/error
          - links: list of executed links (ability results)
          - summary: counts by status
        """
        elapsed = 0
        logger.info(f"Polling operation {operation_id} (timeout={timeout}s)")

        while elapsed < timeout:
            op = self.get_operation(operation_id)
            if not op:
                return {"status": "error", "message": "Operation not found"}

            state = op.get("state", "")
            logger.debug(f"Operation {operation_id} state: {state} ({elapsed}s)")

            if state in ("finished", "cleanup", "out_of_time"):
                links = self._get_operation_links(operation_id)
                return {
                    "status": "finished",
                    "operation_id": operation_id,
                    "state": state,
                    "links": links,
                    "summary": self._summarize_links(links),
                }

            time.sleep(poll_interval)
            elapsed += poll_interval

        return {
            "status": "timeout",
            "operation_id": operation_id,
            "elapsed": elapsed,
        }

    def stop_operation(self, operation_id: str) -> bool:
        """Stop a running operation."""
        try:
            self._patch(
                f"/api/v2/operations/{operation_id}",
                {"state": "finished"},
            )
            return True
        except Exception:
            return False

    # ── Operation links (results) ─────────────────────────────────────────────

    def _get_operation_links(self, operation_id: str) -> list[dict]:
        """Get all links (executed abilities) for an operation."""
        try:
            resp = self._get(f"/api/v2/operations/{operation_id}/links")
            return resp if isinstance(resp, list) else []
        except Exception:
            return []

    def _summarize_links(self, links: list[dict]) -> dict:
        """Summarize link execution results."""
        status_counts: dict[str, int] = {}
        technique_results: list[dict] = []

        for link in links:
            status = link.get("status", -1)
            status_label = {
                0: "success",
                -2: "discarded",
                -3: "failed",
                -4: "collect",
                1: "running",
            }.get(status, f"unknown({status})")

            status_counts[status_label] = status_counts.get(status_label, 0) + 1

            ability = link.get("ability", {})
            technique_results.append({
                "ability_id": ability.get("ability_id", ""),
                "ability_name": ability.get("name", ""),
                "technique_id": ability.get("technique_id", ""),
                "status": status_label,
                "output": link.get("output", ""),
                "agent_paw": link.get("paw", ""),
            })

        return {
            "total_links": len(links),
            "by_status": status_counts,
            "technique_results": technique_results,
            "success_rate": (
                status_counts.get("success", 0) / len(links)
                if links else 0.0
            ),
        }

    # ── Full pipeline ─────────────────────────────────────────────────────────

    def run_gap_validation(
        self,
        technique_ids: list[str],
        operation_name: str = "Meridian Gap Validation",
        platform: str = "windows",
        agent_group: str = "red",
        poll_timeout: int = 600,
        dry_run: bool = True,
    ) -> dict:
        """
        Full Scope B pipeline:
          1. Find abilities matching technique IDs from live Caldera
          2. Create adversary profile
          3. Launch operation
          4. Poll for results

        Parameters
        ----------
        technique_ids : ATT&CK technique IDs to validate
        operation_name : name for the Caldera operation
        platform : filter abilities by platform
        agent_group : Caldera agent group to run against
        poll_timeout : seconds to wait for operation completion
        dry_run : if True, find abilities and create profile but don't launch

        Returns
        -------
        Validation result dict
        """
        # Step 1: Health check
        health = self.health_check()
        if health["status"] != "ok":
            return {"status": "caldera_unavailable", "health": health}

        logger.info(f"Caldera connected — {health['abilities_count']} abilities")

        # Step 2: Find matching abilities
        ability_map = self.find_abilities_for_techniques(technique_ids, platform)
        matched_abilities = []
        unmapped_techniques = []

        for tid, abilities in ability_map.items():
            if abilities:
                # Take first ability per technique
                matched_abilities.append(abilities[0]["ability_id"])
                logger.info(
                    f"  {tid} → {abilities[0]['name']} ({abilities[0]['ability_id']})"
                )
            else:
                unmapped_techniques.append(tid)
                logger.warning(f"  {tid} → no matching ability")

        if not matched_abilities:
            return {
                "status": "no_abilities",
                "unmapped": unmapped_techniques,
            }

        # Step 3: Create adversary profile
        adversary_id = self.create_adversary(
            name=f"{operation_name} — Profile",
            description=f"Auto-generated for gap validation. Techniques: {', '.join(technique_ids)}",
            ability_ids=matched_abilities,
        )

        if dry_run:
            return {
                "status": "dry_run",
                "adversary_id": adversary_id,
                "ability_count": len(matched_abilities),
                "mapped_techniques": [t for t in technique_ids if t not in unmapped_techniques],
                "unmapped_techniques": unmapped_techniques,
                "message": "Profile created in Caldera. Run without dry_run to launch operation.",
            }

        # Step 4: Check agents
        agents = self.list_agents()
        group_agents = [a for a in agents if a.get("group") == agent_group]
        if not group_agents:
            return {
                "status": "no_agents",
                "adversary_id": adversary_id,
                "message": f"No agents in group '{agent_group}'. Deploy a Sandcat agent first.",
            }

        logger.info(f"Found {len(group_agents)} agent(s) in group '{agent_group}'")

        # Step 5: Launch operation
        op_id = self.create_operation(
            name=operation_name,
            adversary_id=adversary_id,
            agent_group=agent_group,
        )

        # Step 6: Poll for results
        results = self.poll_operation(op_id, timeout=poll_timeout)
        results["adversary_id"] = adversary_id
        results["technique_ids"] = technique_ids
        results["unmapped_techniques"] = unmapped_techniques

        return results

    # ── HTTP helpers ──────────────────────────────────────────────────────────

    def _get(self, path: str) -> Any:
        with httpx.Client(timeout=self._timeout) as client:
            resp = client.get(f"{self._url}{path}", headers=self._headers)
            resp.raise_for_status()
            return resp.json()

    def _post(self, path: str, payload: dict) -> Any:
        with httpx.Client(timeout=self._timeout) as client:
            resp = client.post(
                f"{self._url}{path}",
                headers=self._headers,
                json=payload,
            )
            resp.raise_for_status()
            return resp.json() if resp.content else {}

    def _put(self, path: str, payload: dict) -> Any:
        with httpx.Client(timeout=self._timeout) as client:
            resp = client.put(
                f"{self._url}{path}",
                headers=self._headers,
                json=payload,
            )
            resp.raise_for_status()
            return resp.json() if resp.content else {}

    def _patch(self, path: str, payload: dict) -> Any:
        with httpx.Client(timeout=self._timeout) as client:
            resp = client.patch(
                f"{self._url}{path}",
                headers=self._headers,
                json=payload,
            )
            resp.raise_for_status()
            return resp.json() if resp.content else {}

    def _delete(self, path: str) -> None:
        with httpx.Client(timeout=self._timeout) as client:
            resp = client.delete(f"{self._url}{path}", headers=self._headers)
            resp.raise_for_status()
