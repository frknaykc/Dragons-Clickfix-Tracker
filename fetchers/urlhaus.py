import requests
import csv
import io
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from core.iocs import observed_at

URLHAUS_RECENT_CSV = "https://urlhaus.abuse.ch/downloads/csv_recent/"
TARGET_TAGS = {
    "clickfix", "clearfake", "etherhiding", "stealc",
    "lumma", "amos", "macsync", "fakeupdate", "fake-update", "smartcontract"
}

def fetch_urlhaus_recent(limit: int = 150, time_window_minutes: int = 1440) -> list[dict]:
    """Fetch URLhaus listings added within the same UTC window as urlscan."""
    if time_window_minutes <= 0:
        raise ValueError("time_window_minutes must be positive")
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=time_window_minutes)
    candidates = []
    try:
        resp = requests.get(URLHAUS_RECENT_CSV, timeout=12)
        if resp.status_code != 200:
            print(f"[!] URLhaus returned status {resp.status_code}")
            return []

        lines = [l for l in resp.text.splitlines() if not l.startswith('#') and l.strip()]
        reader = csv.reader(io.StringIO('\n'.join(lines)))

        for row in reader:
            if len(row) < 7:
                continue

            date_added = row[1]
            observed = observed_at(date_added)
            if observed is None or not cutoff <= observed <= now:
                continue
            raw_url = row[2]
            status = row[3]
            threat = row[5]
            tags = row[6]
            tags_lower = tags.lower()

            # Check if any target tag is present
            matched_tag = None
            for t in TARGET_TAGS:
                if t in tags_lower:
                    matched_tag = t
                    break

            if matched_tag:
                parsed = urlparse(raw_url)
                domain = parsed.hostname or ""

                candidates.append({
                    "scan_id": f"urlhaus_{row[0]}",
                    "domain": domain,
                    "url": raw_url,
                    "threat_type": f"URLhaus: {threat} ({tags})",
                    "source": "abuse.ch (URLhaus)",
                    "first_seen": date_added,
                    "status": status,
                    "report_url": row[7] if len(row) > 7 else raw_url,
                    "matched_tag": matched_tag
                })

                if len(candidates) >= limit:
                    break

    except Exception as e:
        print(f"[!] Error fetching URLhaus feed: {e}")

    return candidates
