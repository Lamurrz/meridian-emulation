"""
selector/technique_selector.py
--------------------------------
Queries the Meridian Risk API for control gaps and maps the resulting
ATT&CK technique IDs to available Atomic Red Team tests.

This is the bridge between Meridian's threat intelligence and the
emulation runner — it answers: "which techniques have no active
mitigation AND have atomic tests available?"
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from catalog.atomic_catalog import AtomicCatalog
from config import settings

logger = logging.getLogger("emulation.selector")


class TechniqueSelector:
    """
    Selects ATT&CK techniques for emulation based on:
      1. Meridian control gaps (techniques targeting assets with no mitigation)
      2. Availability of atomic tests for those techniques
      3. Optional filters: platform, AI-relevance, risk score threshold
    """

    def __init__(self, catalog: AtomicCatalog = None):
        self._catalog = catalog or AtomicCatalog()
        self._meridian_base = settings.meridian_api_url.rstrip("/")
        self._timeout = settings.meridian_timeout

    # ── Meridian queries ──────────────────────────────────────────────────────

    def get_control_gaps(self) -> list[dict]:
        """
        Fetch control gaps from Meridian: techniques that target AI assets
        with no active mitigating control.
        """
        try:
            resp = httpx.get(
                f"{self._meridian_base}/controls/gaps",
                timeout=self._timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            gaps = data.get("gaps", [])
            logger.info(f"Meridian returned {len(gaps)} control gaps")
            return gaps
        except Exception as exc:
            logger.warning(f"Meridian unavailable ({exc}) — using empty gap list")
            return []

    def get_high_risk_assets(self, min_score: float = 7.0) -> list[dict]:
        """
        Fetch assets with risk score above threshold.
        Used to prioritize techniques that target high-value assets.
        """
        try:
            resp = httpx.get(
                f"{self._meridian_base}/assets",
                timeout=self._timeout,
            )
            resp.raise_for_status()
            assets = resp.json()
            high_risk = [a for a in assets if (a.get("risk_score") or 0) >= min_score]
            logger.info(f"{len(high_risk)} high-risk assets (score ≥ {min_score})")
            return high_risk
        except Exception as exc:
            logger.warning(f"Could not fetch assets: {exc}")
            return []

    # ── Technique selection ───────────────────────────────────────────────────

    def select_techniques(
        self,
        platform: str = None,
        max_techniques: int = 20,
        ai_relevant_only: bool = True,
        min_risk_score: float = 0.0,
        technique_ids: list[str] | None = None,
    ) -> list[dict]:
        """
        Select ATT&CK techniques for emulation.

        Priority order:
          1. Techniques from Meridian control gaps (no active mitigation)
          2. Techniques targeting high-risk assets
          3. All techniques with atomic tests (if Meridian unavailable)

        Parameters
        ----------
        platform        : Filter to tests supporting this OS (windows/linux/macos)
        max_techniques  : Maximum number of techniques to return
        ai_relevant_only: Filter to AI/ML-relevant techniques only
        min_risk_score  : Only include techniques targeting assets above this score
        technique_ids   : If provided, use these IDs instead of querying Meridian

        Returns
        -------
        List of technique dicts with atomic test info attached.
        """
        platform = platform or settings.execution_platform

        # ── Get candidate technique IDs ───────────────────────────────────────
        if technique_ids:
            candidate_ids = technique_ids
            gap_technique_ids = set(technique_ids)
            priority_ids = set(technique_ids)
            logger.info(f"Using {len(candidate_ids)} explicitly provided technique IDs")
        else:
            gaps = self.get_control_gaps()
            gap_technique_ids = {g.get("technique_id", "") for g in gaps if g.get("technique_id")}
            logger.info(f"Gap techniques: {sorted(gap_technique_ids)}")

            # Also get techniques from high-risk asset paths
            high_risk_assets = self.get_high_risk_assets(min_risk_score) if min_risk_score > 0 else []
            high_risk_technique_ids = set()
            for asset in high_risk_assets:
                for tid in asset.get("technique_ids", []):
                    high_risk_technique_ids.add(tid)

            # Combine: gaps first (highest priority), then high-risk asset techniques
            priority_ids = gap_technique_ids
            candidate_ids = list(gap_technique_ids | high_risk_technique_ids)

            if not candidate_ids:
                logger.warning("No techniques from Meridian — falling back to AI-relevant catalog")
                self._catalog.load_index()
                all_ids = self._catalog.available_technique_ids()
                candidate_ids = self._catalog.filter_by_ai_relevance(all_ids)

        # ── Expand base technique IDs to subtechniques ───────────────────────
        # Atomic tests are stored at subtechnique level (T1110.001, not T1110)
        # Expand any base IDs to all available subtechniques in the catalog
        expanded = []
        all_available = self._catalog.available_technique_ids()
        for tid in candidate_ids:
            if '.' in tid:
                expanded.append(tid)  # already a subtechnique
            else:
                # Find all subtechniques in catalog
                subs = [t for t in all_available if t.startswith(tid + '.')]
                if subs:
                    expanded.extend(subs)
                else:
                    expanded.append(tid)  # keep base ID, may have direct atomic
        candidate_ids = list(set(expanded))

        # ── Filter by AI relevance ─────────────────────────────────────────────
        if ai_relevant_only:
            filtered = self._catalog.filter_by_ai_relevance(candidate_ids)
            # Keep any gap techniques even if not in AI-relevant list
            filtered = list(set(filtered) | (gap_technique_ids & set(candidate_ids)))
            logger.info(f"After AI-relevance filter: {len(filtered)} techniques")
        else:
            filtered = candidate_ids

        # ── Check atomic availability ─────────────────────────────────────────
        atomics = self._catalog.get_atomics_for_techniques(filtered, platform=platform)
        logger.info(f"Atomic tests available for {len(atomics)} of {len(filtered)} techniques")

        # ── Build selection with priority scoring ─────────────────────────────
        selections = []
        for tid, atomic in atomics.items():
            is_gap = tid in priority_ids
            test_count = len(atomic.get("atomic_tests", []))

            selection = {
                "technique_id": tid,
                "display_name": atomic.get("display_name", ""),
                "is_control_gap": is_gap,
                "test_count": test_count,
                "platforms": list({
                    p
                    for t in atomic.get("atomic_tests", [])
                    for p in t.get("supported_platforms", [])
                }),
                "atomic_tests": atomic.get("atomic_tests", []),
                "priority_score": (10 if is_gap else 5) + test_count,
            }
            selections.append(selection)

        # Sort: control gaps first, then by test count
        selections.sort(key=lambda x: x["priority_score"], reverse=True)
        selections = selections[:max_techniques]

        logger.info(
            f"Selected {len(selections)} techniques "
            f"({sum(1 for s in selections if s['is_control_gap'])} are control gaps)"
        )
        return selections

    def selection_summary(self, selections: list[dict]) -> dict:
        """Return a summary of the technique selection."""
        total_tests = sum(s["test_count"] for s in selections)
        gap_count = sum(1 for s in selections if s["is_control_gap"])

        return {
            "total_techniques": len(selections),
            "control_gap_techniques": gap_count,
            "non_gap_techniques": len(selections) - gap_count,
            "total_atomic_tests": total_tests,
            "techniques": [
                {
                    "id": s["technique_id"],
                    "name": s["display_name"],
                    "is_gap": s["is_control_gap"],
                    "test_count": s["test_count"],
                }
                for s in selections
            ],
        }
