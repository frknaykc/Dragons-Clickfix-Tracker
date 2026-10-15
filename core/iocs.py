"""Typed indicators extracted from scan observations, without host-wide guilt by association."""

from datetime import datetime, timezone
from urllib.parse import urlsplit


IOC_TYPES = {"c2_host", "tds_delivery_url", "payload_url", "extracted_url", "malware_download_url", "smart_contract"}


def host_of(url):
    try:
        parts = urlsplit(url)
        host = parts.hostname
        return host.lower().rstrip(".") if parts.scheme in ("http", "https") and host else None
    except (TypeError, ValueError, AttributeError):
        return None


def valid_url(url):
    return isinstance(url, str) and bool(host_of(url)) and not any(c.isspace() for c in url)


def observed_at(value):
    if not value:
        return None
    try:
        date = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if date.tzinfo is None:
            date = date.replace(tzinfo=timezone.utc)
        return date.astimezone(timezone.utc)
    except (AttributeError, TypeError, ValueError):
        return None


def indicators_for_scan(scan):
    """Return (type, value, evidence) tuples; generic page hosts are NOT IOCs."""
    found = {}

    def add(kind, value, evidence):
        if kind == "smart_contract":
            if not isinstance(value, str) or len(value) != 42 or not value.startswith("0x"):
                return
        elif kind == "c2_host":
            if not value or "." not in value:
                return
        elif not valid_url(value):
            return
        found[(kind, value)] = evidence

    source = scan.get("source")
    if source == "abuse.ch (URLhaus)":
        add("malware_download_url", scan.get("url"), "urlhaus_listing")
    else:
        delivery = scan.get("delivery_url")
        c2 = scan.get("live_c2_url")
        # Legacy is_clearfake also covered broad ClickFix lure matches. Require the
        # characteristic loader endpoint before assigning delivery/C2 semantics.
        if scan.get("is_clearfake") and valid_url(delivery) and \
                urlsplit(delivery).path == "/api.php" and \
                urlsplit(delivery).query.startswith("s="):
            add("tds_delivery_url", delivery, "clearfake_loader")
            host = host_of(c2) if c2 and host_of(c2) == host_of(delivery) else host_of(delivery)
            add("c2_host", host, "clearfake_loader")
        if scan.get("smart_contract") and scan.get("is_clearfake"):
            add("smart_contract", scan["smart_contract"], "clearfake_loader")
        for url, evidence in scan.get("url_evidence", {}).items():
            kind = "payload_url" if evidence in ("clipboard_command", "powershell_command", "mshta_download", "staging_command") else "extracted_url"
            add(kind, url, evidence)
        # Older scans did not retain per-URL provenance. Do not upgrade them to verified payloads.
        for url in scan.get("extracted_b64_urls", []):
            if url not in scan.get("url_evidence", {}):
                add("extracted_url", url, "legacy_extraction")
    # A delivery URL is more specific than a generic extracted URL for the same value.
    for kind, value in list(found):
        if ("tds_delivery_url", value) in found and kind == "extracted_url":
            del found[(kind, value)]
    return [(kind, value, evidence) for (kind, value), evidence in sorted(found.items())]


def compact_scan(scan):
    fields = ("scan_id", "domain", "url", "source", "status", "report_url", "first_seen",
              "is_clearfake", "is_cfmd", "is_mshta", "cfmd_lure", "smart_contract",
              "method_hash", "live_c2_url", "delivery_url", "extracted_b64_urls", "url_evidence")
    compact = {key: scan[key] for key in fields if scan.get(key) is not None}
    if "source" not in compact:
        compact["source"] = "urlscan.io" if not str(scan.get("scan_id", "")).startswith("urlhaus_") else "abuse.ch (URLhaus)"
    return compact


def merge_scan(database, scan):
    """Aggregate typed IOCs. Returns newly created records for the daily CSV."""
    new_records = []
    date = observed_at(scan.get("first_seen"))
    first_seen = date.isoformat().replace("+00:00", "Z") if date else scan.get("first_seen")
    for kind, value, evidence in indicators_for_scan(scan):
        key = f"{kind}|{value}"
        if key not in database:
            database[key] = {"type": kind, "value": value, "first_seen": first_seen,
                             "last_seen": first_seen, "evidence": [], "sources": [], "references": []}
            new_records.append(database[key])
        item = database[key]
        if first_seen and (not item.get("first_seen") or first_seen < item["first_seen"]):
            item["first_seen"] = first_seen
        if first_seen and (not item.get("last_seen") or first_seen > item["last_seen"]):
            item["last_seen"] = first_seen
        for field, entry in (("evidence", evidence), ("sources", scan.get("source")),
                             ("references", scan.get("report_url"))):
            if entry and entry not in item[field]:
                item[field].append(entry)
    return new_records
