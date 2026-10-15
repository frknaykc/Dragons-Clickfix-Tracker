"""One-time conversion of the historical scan-keyed iocs.json into typed IOCs.

The original tracked file remains recoverable in Git history; old daily CSVs are untouched.
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.iocs import compact_scan, indicators_for_scan, merge_scan, observed_at  # noqa: E402


def migrate(old_path, scans_path, ioc_path):
    old_path, scans_path, ioc_path = map(Path, (old_path, scans_path, ioc_path))
    if scans_path.exists():
        raise FileExistsError(f"Refusing to overwrite scan archive: {scans_path}")
    legacy = json.loads(old_path.read_text(encoding="utf-8"))
    if not isinstance(legacy, dict) or any(not isinstance(v, dict) or "scan_id" not in v for v in legacy.values()):
        raise ValueError("Expected legacy scan-keyed iocs.json")
    scans = {}
    iocs = {}
    for scan in sorted(legacy.values(), key=lambda s: observed_at(s.get("first_seen")) or datetime(1970, 1, 1, tzinfo=timezone.utc)):
        compact = compact_scan(scan)
        scans[compact["scan_id"]] = compact
        merge_scan(iocs, compact)
    # No generated file is changed until the full conversion succeeds.
    scans_path.write_text(json.dumps(scans, indent=2, ensure_ascii=False), encoding="utf-8")
    ioc_path.write_text(json.dumps(iocs, indent=2, ensure_ascii=False), encoding="utf-8")
    return scans, iocs


def rebuild_from_scans(scans_path, ioc_path):
    """Rebuild only derived IOCs from the preserved observation archive."""
    scans = json.loads(Path(scans_path).read_text(encoding="utf-8"))
    iocs = {}
    for scan in sorted(scans.values(), key=lambda s: observed_at(s.get("first_seen")) or datetime(1970, 1, 1, tzinfo=timezone.utc)):
        merge_scan(iocs, scan)
    Path(ioc_path).write_text(json.dumps(iocs, indent=2, ensure_ascii=False), encoding="utf-8")
    return scans, iocs


if __name__ == "__main__":
    from main import generate_markdown_report, update_domains_list

    os.chdir(ROOT)
    if sys.argv[1:] == ["--rebuild"]:
        scans, iocs = rebuild_from_scans("data/scans.json", "data/iocs.json")
    elif not sys.argv[1:]:
        scans, iocs = migrate("data/iocs.json", "data/scans.json", "data/iocs.json")
    else:
        raise SystemExit("Usage: python scripts/migrate_iocs.py [--rebuild]")
    update_domains_list(iocs)
    times = [date for s in scans.values() if (date := observed_at(s.get("first_seen")))]
    if times:
        last_day = max(times).date()
        keys = {f"{kind}|{value}" for s in scans.values()
                if (date := observed_at(s.get("first_seen"))) and date.date() == last_day
                for kind, value, _ in indicators_for_scan(s)}
        generate_markdown_report([iocs[key] for key in keys], max(times).isoformat().replace("+00:00", "Z"))
    print(f"Migrated {len(scans)} scans into {len(iocs)} typed IOCs.")
