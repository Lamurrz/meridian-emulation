"""
caldera/caldera_profile_generator.py
--------------------------------------
Scope A: Adversary profile generator — no running Caldera instance required.

Reads Meridian control gaps (techniques targeting assets with no mitigation)
and generates Caldera-compatible adversary profile YAMLs that can be loaded
directly into a Caldera instance by dropping them into:

  caldera/data/adversaries/

Each generated profile represents a gap-driven adversary — a collection of
abilities mapped to the unmitigated techniques targeting your AI assets.

Caldera adversary profile format
----------------------------------
id: <uuid>
name: <profile name>
description: <description>
objective: 495a9828-cab1-44dd-a0ca-66e58177d8cc  # default objective
atomic_ordering:
  - <ability_id_1>
  - <ability_id_2>

The atomic_ordering is a list of ability UUIDs from Caldera's Stockpile plugin.
This generator maps ATT&CK/ATLAS technique IDs to known Stockpile ability IDs.

Usage
-----
python caldera/caldera_profile_generator.py --output-dir /path/to/caldera/data/adversaries
python caldera/caldera_profile_generator.py --output-dir ./data/caldera_profiles --dry-run
python caldera/caldera_profile_generator.py --techniques T1110 T1078 T1021 --output-dir ./profiles
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import yaml

logger = logging.getLogger("emulation.caldera")

# ── Stockpile ability library ─────────────────────────────────────────────────
# Maps ATT&CK technique IDs to known Caldera Stockpile ability UUIDs.
# These are the default abilities shipped with the Stockpile plugin.
# Source: plugins/stockpile/data/abilities/
#
# Format: technique_id → list of (ability_id, name, tactic, platform)
# Multiple abilities may implement the same technique across platforms.

TECHNIQUE_TO_ABILITIES: dict[str, list[dict]] = {
    # Credential Access — verified from live Caldera instance
    "T1003.001": [
        {"id": "7049e3ec-b822-4fdf-a4ac-18190f9b66d1", "name": "Powerkatz (Staged)",
         "tactic": "credential-access", "platform": "windows"},
        {"id": "baac2c6d-4652-4b7e-ab0a-f1bf246edd12", "name": "Run PowerKatz",
         "tactic": "credential-access", "platform": "windows"},
    ],
    "T1040": [
        {"id": "1b4fb81c-8090-426c-93ab-0a633e7a16a7", "name": "Sniff network traffic",
         "tactic": "credential-access", "platform": "windows"},
    ],
    # Discovery — verified from live Caldera instance
    "T1057": [
        {"id": "4d9b079c-9ede-4116-8b14-72ad3a5533af", "name": "PowerShell Process Enumeration",
         "tactic": "discovery", "platform": "windows"},
        {"id": "5a39d7ed-45c9-4a79-b581-e5fb99e24f65", "name": "System processes",
         "tactic": "discovery", "platform": "windows"},
        {"id": "335cea7b-bec0-48c6-adfb-6066070f5f68", "name": "View Processes",
         "tactic": "discovery", "platform": "windows"},
    ],
    "T1082": [
        {"id": "29451844-9b76-4e16-a9ee-d6feab4b24db", "name": "PowerShell version",
         "tactic": "discovery", "platform": "windows"},
        {"id": "b6f545ef-f802-4537-b59d-2cb19831c8ed", "name": "Snag broadcast IP",
         "tactic": "discovery", "platform": "windows"},
    ],
    "T1083": [
        {"id": "6e1a53c0-7352-4899-be35-fa7f364d5722", "name": "Print Working Directory",
         "tactic": "discovery", "platform": "windows"},
    ],
    "T1012": [
        {"id": "2488245e-bcbd-405d-920e-2de27db882b3", "name": "Query Registry",
         "tactic": "discovery", "platform": "windows"},
    ],
    "T1016": [
        {"id": "e8017c46-acb8-400c-a4b5-b3362b5b5baa", "name": "Network Interface Configuration",
         "tactic": "discovery", "platform": "windows"},
    ],
    "T1046": [
        {"id": "5a4cb2be-2684-4801-9355-3a90c91e0004", "name": "Network Service Scanning",
         "tactic": "discovery", "platform": "windows"},
    ],
    "T1135": [
        {"id": "530e47c6-8592-42bf-91df-c59ffbd8541b", "name": "View admin shares",
         "tactic": "discovery", "platform": "windows"},
    ],
    "T1201": [
        {"id": "e82f39e2-56f8-4f19-8376-b007f9ac5f8a", "name": "Password Policy",
         "tactic": "discovery", "platform": "windows"},
    ],
    "T1069.001": [
        {"id": "5c4dd985-89e3-4590-9b57-71fed66ff4e2", "name": "Permission Groups Discovery",
         "tactic": "discovery", "platform": "windows"},
    ],
    "T1518.001": [
        {"id": "7c42a30c-c8c7-44c5-80a8-862d364ac1e4", "name": "UAC Status",
         "tactic": "discovery", "platform": "windows"},
    ],
    # Lateral Movement — verified from live Caldera instance
    "T1021.002": [
        {"id": "aa6ec4dd-db09-4925-b9b9-43adeb154686", "name": "Mount Share",
         "tactic": "lateral-movement", "platform": "windows"},
        {"id": "40161ad0-75bd-11e9-b475-0800200c9a66", "name": "Net use",
         "tactic": "lateral-movement", "platform": "windows"},
    ],
    "T1021.006": [
        {"id": "41bb2b7a-75af-49fd-bd15-6c827df25921", "name": "Start Agent (WinRM)",
         "tactic": "lateral-movement", "platform": "windows"},
    ],
    # Execution — verified from live Caldera instance
    "T1059.001": [
        {"id": "702bfdd2-9947-4eda-b551-c3a1ea9a59a2", "name": "PowerShell information gathering",
         "tactic": "collection", "platform": "windows"},
        {"id": "e5f9de8f-3df1-4e78-ad92-a784e3f6770d", "name": "Move Powershell and triage",
         "tactic": "defense-evasion", "platform": "windows"},
    ],
    "T1047": [
        {"id": "94f21386-9547-43c4-99df-938ab05d45ce", "name": "WMIC Process Enumeration",
         "tactic": "collection", "platform": "windows"},
    ],
    "T1569.002": [
        {"id": "95ad5d69-563e-477b-802b-4855bfb3be09", "name": "Service Creation",
         "tactic": "execution", "platform": "windows"},
    ],
    # Collection — verified from live Caldera instance
    "T1113": [
        {"id": "316251ed-6a28-4013-812b-ddf5b5b007f8", "name": "Screen Capture",
         "tactic": "collection", "platform": "windows"},
    ],
    "T1005": [
        {"id": "90c2efaa-8205-480d-8bb6-61d90dbaf81b", "name": "Find sensitive files",
         "tactic": "collection", "platform": "windows"},
    ],
    "T1074.001": [
        {"id": "4e97e699-93d7-4040-b5a3-2e906a58199e", "name": "Stage sensitive files",
         "tactic": "collection", "platform": "windows"},
    ],
    # Exfiltration — verified from live Caldera instance
    "T1029": [
        {"id": "110cea7a-5b03-4443-92ee-7ccefaead451", "name": "Scheduled Exfiltration",
         "tactic": "exfiltration", "platform": "windows"},
    ],
    "T1537": [
        {"id": "ba0deadb-97ac-4a4c-aa81-21912fc90980", "name": "Transfer to S3",
         "tactic": "exfiltration", "platform": "windows"},
    ],
    # Privilege Escalation — verified from live Caldera instance
    "T1548.002": [
        {"id": "665432a4-42e7-4ee1-af19-a9a8c9455d0c", "name": "UAC bypass registry",
         "tactic": "privilege-escalation", "platform": "windows"},
        {"id": "b7344901-0b02-4ead-baf6-e3f629ed545f", "name": "Slui File Handler Hijack",
         "tactic": "privilege-escalation", "platform": "windows"},
    ],
    # Defense Evasion — verified from live Caldera instance
    "T1055.002": [
        {"id": "e5bcefee-262d-4568-a261-e8a20855ec81", "name": "Signed Binary Execution - Mavinject",
         "tactic": "defense-evasion", "platform": "windows"},
    ],
    "T1055.001": [
        {"id": "a74bc239-a196-4f7e-8d5c-fe8c0266071c", "name": "Signed Binary Execution - odbcconf",
         "tactic": "defense-evasion", "platform": "windows"},
    ],
    # Persistence — verified from live Caldera instance
    "T1543.003": [
        {"id": "52771610-2322-44cf-816b-a7df42b4c086", "name": "Replace a service binary",
         "tactic": "persistence", "platform": "windows"},
    ],
}

# Default Caldera objective UUID (built-in "default" objective)
DEFAULT_OBJECTIVE = "495a9828-cab1-44dd-a0ca-66e58177d8cc"

# Tactic ordering for profile construction (follows ATT&CK kill chain)
TACTIC_ORDER = [
    "initial-access", "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery", "lateral-movement",
    "collection", "exfiltration", "command-and-control",
]


class CalderaProfileGenerator:
    """
    Generates Caldera adversary profile YAMLs from Meridian control gaps.
    No running Caldera instance required — produces files for manual import.
    """

    def __init__(
        self,
        meridian_url: str = "http://127.0.0.1:8000",
        output_dir: str = "data/caldera_profiles",
        timeout: int = 10,
    ):
        self._meridian = meridian_url.rstrip("/")
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._timeout = timeout

    # ── Main entry point ──────────────────────────────────────────────────────

    def generate(
        self,
        technique_ids: list[str] | None = None,
        profile_name: str | None = None,
        platform: str = "windows",
        split_by_tactic: bool = False,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """
        Generate adversary profile(s) from Meridian control gaps or explicit technique IDs.

        Parameters
        ----------
        technique_ids   : explicit list of ATT&CK technique IDs (overrides Meridian)
        profile_name    : name for the generated profile
        platform        : filter abilities to this platform
        split_by_tactic : generate one profile per tactic (vs one combined profile)
        dry_run         : show what would be generated without writing files

        Returns
        -------
        Generation result dict with profile paths and ability mappings.
        """
        # Get technique IDs
        if technique_ids:
            techniques = [{"technique_id": t, "is_gap": False} for t in technique_ids]
            source = "explicit"
        else:
            techniques = self._get_gap_techniques()
            source = "meridian_gaps"

        if not techniques:
            logger.warning("No techniques to generate profiles for")
            return {"status": "no_techniques", "profiles": []}

        logger.info(f"Generating Caldera profile(s) for {len(techniques)} techniques "
                    f"(source: {source})")

        # Map techniques to abilities
        ability_map = self._map_to_abilities(techniques, platform)
        logger.info(f"Mapped {len(ability_map['mapped'])} techniques to abilities, "
                    f"{len(ability_map['unmapped'])} unmapped")

        if not ability_map["mapped"]:
            logger.warning("No techniques mapped to Caldera abilities")
            return {
                "status": "no_abilities",
                "unmapped": ability_map["unmapped"],
                "note": "These techniques have no matching Caldera Stockpile abilities. "
                        "Custom abilities would need to be created in Caldera.",
            }

        # Generate profile(s)
        profiles = []
        if split_by_tactic:
            profiles = self._generate_per_tactic(ability_map, profile_name, platform, dry_run)
        else:
            profile = self._generate_combined(ability_map, profile_name, platform, dry_run)
            profiles = [profile]

        return {
            "status": "success",
            "source": source,
            "total_techniques": len(techniques),
            "mapped_techniques": len(ability_map["mapped"]),
            "unmapped_techniques": len(ability_map["unmapped"]),
            "profiles_generated": len(profiles),
            "profiles": profiles,
            "unmapped": ability_map["unmapped"],
            "output_dir": str(self._output_dir),
            "next_step": (
                f"Copy the YAML file(s) to caldera/data/adversaries/ "
                f"and restart Caldera to load the profile(s)."
                if not dry_run else
                "Dry-run — no files written."
            ),
        }

    # ── Meridian integration ──────────────────────────────────────────────────

    def _get_gap_techniques(self) -> list[dict]:
        """Fetch control gap techniques from Meridian."""
        try:
            resp = httpx.get(
                f"{self._meridian}/controls/gaps",
                timeout=self._timeout,
            )
            resp.raise_for_status()
            gaps = resp.json().get("gaps", [])
            techniques = [
                {"technique_id": g.get("technique_id", ""), "is_gap": True,
                 "asset_id": g.get("asset_id", ""), "technique_name": g.get("technique_name", "")}
                for g in gaps if g.get("technique_id")
            ]
            logger.info(f"Fetched {len(techniques)} gap techniques from Meridian")
            return techniques
        except Exception as exc:
            logger.warning(f"Meridian unavailable ({exc}) — use --techniques to specify manually")
            return []

    # ── Ability mapping ───────────────────────────────────────────────────────

    def _map_to_abilities(
        self, techniques: list[dict], platform: str
    ) -> dict[str, list]:
        """Map technique IDs to Caldera Stockpile ability IDs."""
        mapped = []
        unmapped = []

        seen_ability_ids = set()

        for tech in techniques:
            tid = tech.get("technique_id", "")
            base_tid = tid.split(".")[0]

            # Try exact match first, then base technique
            abilities = (
                TECHNIQUE_TO_ABILITIES.get(tid) or
                TECHNIQUE_TO_ABILITIES.get(base_tid) or
                []
            )

            # Filter by platform
            platform_abilities = [
                a for a in abilities
                if a.get("platform", "").lower() == platform.lower()
            ]
            if not platform_abilities:
                platform_abilities = abilities  # fall back to any platform

            if platform_abilities:
                for ability in platform_abilities:
                    if ability["id"] not in seen_ability_ids:
                        seen_ability_ids.add(ability["id"])
                        mapped.append({
                            "technique_id": tid,
                            "technique_name": tech.get("technique_name", ""),
                            "is_gap": tech.get("is_gap", False),
                            "ability_id": ability["id"],
                            "ability_name": ability["name"],
                            "tactic": ability["tactic"],
                            "platform": ability["platform"],
                        })
            else:
                unmapped.append({
                    "technique_id": tid,
                    "technique_name": tech.get("technique_name", ""),
                    "reason": "No matching Stockpile ability — custom ability needed",
                })

        return {"mapped": mapped, "unmapped": unmapped}

    # ── Profile generation ────────────────────────────────────────────────────

    def _generate_combined(
        self,
        ability_map: dict,
        profile_name: str | None,
        platform: str,
        dry_run: bool,
    ) -> dict:
        """Generate a single combined adversary profile."""
        name = profile_name or f"Meridian Gap Profile — {datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
        profile_id = str(uuid.uuid4())

        # Order abilities by tactic (follows ATT&CK kill chain)
        abilities_by_tactic: dict[str, list[str]] = {}
        for ab in ability_map["mapped"]:
            tactic = ab["tactic"]
            abilities_by_tactic.setdefault(tactic, []).append(ab["ability_id"])

        atomic_ordering = []
        for tactic in TACTIC_ORDER:
            atomic_ordering.extend(abilities_by_tactic.get(tactic, []))
        # Add any tactics not in our ordering
        for tactic, ids in abilities_by_tactic.items():
            if tactic not in TACTIC_ORDER:
                atomic_ordering.extend(ids)

        profile = {
            "id": profile_id,
            "name": name,
            "description": (
                f"Auto-generated from Meridian control gaps. "
                f"Covers {len(ability_map['mapped'])} abilities across "
                f"{len(set(ab['technique_id'] for ab in ability_map['mapped']))} ATT&CK techniques. "
                f"Platform: {platform}. Generated: {datetime.now(timezone.utc).isoformat()}"
            ),
            "objective": DEFAULT_OBJECTIVE,
            "atomic_ordering": atomic_ordering,
        }

        if not dry_run:
            path = self._write_profile(profile)
            logger.info(f"Generated profile: {path}")
        else:
            path = f"{self._output_dir}/{self._safe_name(name)}.yml (dry-run)"

        return {
            "profile_id": profile_id,
            "name": name,
            "path": str(path),
            "ability_count": len(atomic_ordering),
            "techniques_covered": list(set(ab["technique_id"] for ab in ability_map["mapped"])),
            "abilities": [
                {"id": ab["ability_id"], "name": ab["ability_name"],
                 "technique": ab["technique_id"], "tactic": ab["tactic"]}
                for ab in ability_map["mapped"]
            ],
        }

    def _generate_per_tactic(
        self,
        ability_map: dict,
        profile_name: str | None,
        platform: str,
        dry_run: bool,
    ) -> list[dict]:
        """Generate one adversary profile per tactic."""
        abilities_by_tactic: dict[str, list] = {}
        for ab in ability_map["mapped"]:
            abilities_by_tactic.setdefault(ab["tactic"], []).append(ab)

        profiles = []
        base_name = profile_name or "Meridian Gap"

        for tactic, abilities in abilities_by_tactic.items():
            name = f"{base_name} — {tactic.replace('-', ' ').title()}"
            profile_id = str(uuid.uuid4())

            profile = {
                "id": profile_id,
                "name": name,
                "description": (
                    f"Auto-generated from Meridian control gaps — {tactic} techniques. "
                    f"Platform: {platform}. Generated: {datetime.now(timezone.utc).isoformat()}"
                ),
                "objective": DEFAULT_OBJECTIVE,
                "atomic_ordering": [ab["ability_id"] for ab in abilities],
            }

            if not dry_run:
                path = self._write_profile(profile)
            else:
                path = f"{self._output_dir}/{self._safe_name(name)}.yml (dry-run)"

            profiles.append({
                "profile_id": profile_id,
                "name": name,
                "tactic": tactic,
                "path": str(path),
                "ability_count": len(abilities),
                "techniques_covered": list(set(ab["technique_id"] for ab in abilities)),
            })

        return profiles

    def _write_profile(self, profile: dict) -> Path:
        """Write adversary profile YAML to output directory."""
        filename = f"{self._safe_name(profile['name'])}.yml"
        path = self._output_dir / filename
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(profile, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
        return path

    @staticmethod
    def _safe_name(name: str) -> str:
        """Convert profile name to a safe filename."""
        return name.lower().replace(" ", "_").replace("—", "-").replace("/", "-")[:60]

    # ── Reporting ─────────────────────────────────────────────────────────────

    def print_summary(self, result: dict) -> None:
        """Print a human-readable generation summary."""
        print(f"\n{'='*60}")
        print(f"  Caldera Profile Generator")
        print(f"{'='*60}")
        print(f"  Status:              {result.get('status', 'unknown')}")
        print(f"  Techniques total:    {result.get('total_techniques', 0)}")
        print(f"  Mapped to abilities: {result.get('mapped_techniques', 0)}")
        print(f"  Unmapped:            {result.get('unmapped_techniques', 0)}")
        print(f"  Profiles generated:  {result.get('profiles_generated', 0)}")

        for profile in result.get("profiles", []):
            print(f"\n  Profile: {profile['name']}")
            print(f"    Path:      {profile['path']}")
            print(f"    Abilities: {profile['ability_count']}")
            print(f"    Techniques: {', '.join(profile.get('techniques_covered', []))}")

        unmapped = result.get("unmapped", [])
        if unmapped:
            print(f"\n  Unmapped techniques ({len(unmapped)}) — need custom Caldera abilities:")
            for u in unmapped:
                print(f"    {u['technique_id']}: {u.get('technique_name', '')} — {u['reason']}")

        if result.get("next_step"):
            print(f"\n  Next step: {result['next_step']}")

        print(f"{'='*60}\n")
