"""Daily append-only indicator export. Older CSV files keep their original schema/rows."""

import csv
import os
from datetime import datetime, timezone

from utils.defang import defang_domain, defang_url

DAILY_DIR = "data/daily"
CSV_HEADERS = ["timestamp", "type", "indicator", "threat_type", "detection_method", "first_seen", "reference"]


def export_to_daily_csv(indicators: list[dict]):
    if not indicators:
        return
    os.makedirs(DAILY_DIR, exist_ok=True)
    now = datetime.now(timezone.utc)
    csv_file = os.path.join(DAILY_DIR, now.strftime("%Y-%m-%d.csv"))
    # Never append new-schema rows under an older daily CSV header.
    if os.path.exists(csv_file) and os.path.getsize(csv_file):
        with open(csv_file, "r", encoding="utf-8", newline="") as f:
            if next(csv.reader(f), []) != CSV_HEADERS:
                csv_file = os.path.join(DAILY_DIR, now.strftime("%Y-%m-%d-iocs.csv"))
    existing = set()
    if os.path.exists(csv_file):
        with open(csv_file, "r", encoding="utf-8", newline="") as f:
            existing = {(row.get("type"), row.get("indicator")) for row in csv.DictReader(f)}
    rows = []
    for item in indicators:
        kind = item["type"]
        indicator = defang_domain(item["value"]) if kind == "c2_host" else defang_url(item["value"])
        key = (kind, indicator)
        if key in existing:
            continue
        existing.add(key)
        rows.append({"timestamp": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
                     "type": kind, "indicator": indicator,
                     "threat_type": ", ".join(item["sources"]),
                     "detection_method": ", ".join(item["evidence"]),
                     "first_seen": item.get("first_seen"),
                     "reference": item["references"][-1] if item["references"] else ""})
    if rows:
        write_header = not os.path.exists(csv_file) or os.path.getsize(csv_file) == 0
        with open(csv_file, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
            if write_header:
                writer.writeheader()
            writer.writerows(rows)
        print(f"[+] Exported {len(rows)} observed IOCs to {csv_file}")
