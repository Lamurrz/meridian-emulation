"""
run.py
------
Meridian Emulation CLI — ATT&CK technique emulation with detection validation.

Usage
-----
# Dry-run: show what would be executed (safe default)
python run.py --mode plan

# Dry-run with specific techniques
python run.py --mode plan --techniques T1110 T1078 T1021

# Dry-run scoped to Meridian control gaps only
python run.py --mode plan --gaps-only

# Live execution (requires --live --confirm)
python run.py --mode run --live --confirm

# Full pipeline: plan + validate against CyberGraph-AD findings
python run.py --mode full

# Catalog management
python run.py --mode catalog          # show cache stats
python run.py --mode catalog --refresh  # force refresh from GitHub
"""

import argparse
import json
import logging
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("emulation")


def mode_catalog(args):
    """Show catalog stats and optionally refresh."""
    from catalog.atomic_catalog import AtomicCatalog
    catalog = AtomicCatalog()

    if args.refresh:
        logger.info("Force-refreshing Atomic Red Team index from GitHub...")
        catalog.load_index(force_refresh=True)
    else:
        catalog.load_index()

    stats = catalog.cache_stats()
    available = catalog.available_technique_ids()
    ai_relevant = catalog.filter_by_ai_relevance(available)

    print(f"\nAtomic Red Team Catalog")
    print(f"  Cached techniques:     {stats['cached_techniques']}")
    print(f"  Available techniques:  {len(available)}")
    print(f"  AI-relevant:           {len(ai_relevant)}")
    print(f"  Cache directory:       {stats['cache_dir']}")
    print(f"  Index cached:          {stats['index_cached']}")

    if args.verbose:
        print(f"\nAI-relevant technique IDs:")
        for tid in sorted(ai_relevant):
            summary = catalog.technique_summary(tid)
            if summary:
                print(f"  {tid}: {summary['display_name']} ({summary['test_count']} tests)")


def mode_plan(args):
    """Generate a dry-run execution plan."""
    from catalog.atomic_catalog import AtomicCatalog
    from selector.technique_selector import TechniqueSelector
    from runner.emulation_runner import EmulationRunner
    from validator.detection_validator import DetectionValidator
    from report.coverage_report import CoverageReporter

    catalog = AtomicCatalog()
    catalog.load_index()

    selector = TechniqueSelector(catalog=catalog)
    technique_ids = args.techniques if args.techniques else None

    selections = selector.select_techniques(
        platform=args.platform,
        max_techniques=args.max_techniques,
        ai_relevant_only=not args.all_techniques,
        technique_ids=technique_ids,
    )

    if not selections:
        print("No techniques selected — check Meridian connection or provide --techniques")
        return

    summary = selector.selection_summary(selections)
    print(f"\nSelected {summary['total_techniques']} techniques "
          f"({summary['control_gap_techniques']} control gaps, "
          f"{summary['total_atomic_tests']} atomic tests)")

    runner = EmulationRunner(dry_run=True)
    plan = runner.dry_run(selections)

    validator = DetectionValidator()
    validation = validator.validate(plan)

    reporter = CoverageReporter(output_dir=args.output_dir)
    report = reporter.generate(plan, validation, summary)

    print(f"\nPlan saved to: {args.output_dir}/")
    return report


def mode_run(args):
    """Execute atomic tests (requires --live --confirm)."""
    from catalog.atomic_catalog import AtomicCatalog
    from selector.technique_selector import TechniqueSelector
    from runner.emulation_runner import EmulationRunner
    from validator.detection_validator import DetectionValidator
    from report.coverage_report import CoverageReporter

    if args.live and not args.confirm:
        print("\n⚠  LIVE EXECUTION requires --confirm flag.")
        print("   This will execute real attack techniques on this system.")
        print("   Add --confirm to proceed.\n")
        sys.exit(1)

    catalog = AtomicCatalog()
    catalog.load_index()

    selector = TechniqueSelector(catalog=catalog)
    technique_ids = args.techniques if args.techniques else None

    selections = selector.select_techniques(
        platform=args.platform,
        max_techniques=args.max_techniques,
        ai_relevant_only=not args.all_techniques,
        technique_ids=technique_ids,
    )

    if not selections:
        print("No techniques selected.")
        return

    summary = selector.selection_summary(selections)

    runner = EmulationRunner(dry_run=not args.live, output_dir=args.output_dir)
    results = runner.run(selections, confirm=args.confirm)

    validator = DetectionValidator()
    validation = validator.validate(results, since_minutes=args.validation_window)

    reporter = CoverageReporter(output_dir=args.output_dir)
    report = reporter.generate(results, validation, summary)

    return report


def mode_full(args):
    """Full pipeline: plan → (optionally execute) → validate → report."""
    if args.live:
        return mode_run(args)
    else:
        return mode_plan(args)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Meridian Emulation — ATT&CK technique emulation with detection validation"
    )
    parser.add_argument(
        "--mode", default="plan",
        choices=["plan", "run", "full", "catalog"],
        help="Execution mode (default: plan)"
    )
    parser.add_argument(
        "--techniques", nargs="+", default=None,
        help="Specific ATT&CK technique IDs (e.g. T1110 T1078)"
    )
    parser.add_argument(
        "--platform", default="windows",
        choices=["windows", "linux", "macos"],
        help="Target platform for atomic test filtering"
    )
    parser.add_argument(
        "--max-techniques", type=int, default=20,
        help="Maximum techniques to select"
    )
    parser.add_argument(
        "--gaps-only", action="store_true",
        help="Only select techniques from Meridian control gaps"
    )
    parser.add_argument(
        "--all-techniques", action="store_true",
        help="Include all techniques, not just AI-relevant ones"
    )
    parser.add_argument(
        "--live", action="store_true",
        help="Enable live execution (default: dry-run)"
    )
    parser.add_argument(
        "--confirm", action="store_true",
        help="Confirm live execution (required with --live)"
    )
    parser.add_argument(
        "--validation-window", type=int, default=30,
        help="Minutes to look back for CyberGraph-AD findings (default: 30)"
    )
    parser.add_argument(
        "--output-dir", default="data/results",
        help="Output directory for reports"
    )
    parser.add_argument(
        "--refresh", action="store_true",
        help="Force refresh of Atomic catalog from GitHub"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Verbose output"
    )

    args = parser.parse_args()
    Path(args.output_dir).mkdir(parents=True, exist_ok=True)

    modes = {
        "plan":    mode_plan,
        "run":     mode_run,
        "full":    mode_full,
        "catalog": mode_catalog,
    }
    modes[args.mode](args)
