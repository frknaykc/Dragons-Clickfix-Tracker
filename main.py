import concurrent.futures
import json
import os

from core.catalog import DetectionCatalog
from core.decoder import PayloadDecoder
from core.iocs import compact_scan, indicators_for_scan, merge_scan, observed_at, valid_url
from fetchers.urlhaus import fetch_urlhaus_recent
from fetchers.urlscan import get_dom, get_recent_candidates
from utils.csv_exporter import export_to_daily_csv
from utils.defang import defang_url

DATABASE_FILE = "data/iocs.json"
SCANS_FILE = "data/scans.json"
DOMAINS_FILE = "data/domains.txt"
REPORT_FILE = "LATEST_REPORT.md"


def load_database(path):
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Invalid database: {path}")
    return data


def save_database(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def update_domains_list(db):
    # DNS cannot block a path. Only C2 hosts extracted from ClearFake evidence go here.
    domains = sorted({item["value"] for item in db.values() if item.get("type") == "c2_host"})
    with open(DOMAINS_FILE, "w", encoding="utf-8") as f:
        for domain in domains:
            f.write(f"{domain}\n")


def generate_markdown_report(observed_iocs, observation_time=None):
    if not observed_iocs:
        return
    report = ["# ClickFix / ClearFake — Latest Observed Indicators",
              f"**Latest scan:** `{observation_time or 'unknown'}`",
              "Historical scan evidence; current availability is not guaranteed.",
              "URLhaus-listed URLs are third-party reports, not independently verified file contents.\n"]
    for kind in ("c2_host", "tds_delivery_url", "payload_url", "malware_download_url", "extracted_url", "smart_contract"):
        items = [item for item in observed_iocs if item["type"] == kind]
        if items:
            report.append(f"\n## {kind}\n")
            for item in sorted(items, key=lambda i: i["value"]):
                ref = item["references"][-1] if item["references"] else None
                citation = f"; [source]({ref})" if ref else ""
                report.append(f"- `{defang_url(item['value'])}` — {', '.join(item['evidence'])}{citation}")
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(report) + "\n")


def analyze_candidate(c: dict) -> dict | None:
    """Only archive concrete extracted URLs or a matched ClearFake contract."""
    try:
        dom = get_dom(c["dom_url"]) if c.get("dom_url") else ""
        clearfake = PayloadDecoder.decode_clearfake_js(dom) if dom else {}
        cfmd = PayloadDecoder.decode_cfmd_captcha(dom) if dom else {}
        mshta = PayloadDecoder.decode_mshta(dom) if dom else {}
        url_evidence = {}
        if dom:
            for url in PayloadDecoder.decode_b64_urls(dom):
                url_evidence[url] = "decoded_base64"
            for url in PayloadDecoder.decode_powershell(dom):
                url_evidence[url] = "powershell_command"
            for url in cfmd.get("staging_urls", []):
                url_evidence[url] = "staging_command"
            for url in mshta.get("staging_urls", []):
                url_evidence[url] = "mshta_download"
        if c.get("source") != "abuse.ch (URLhaus)" and not (
            any(valid_url(url) for url in url_evidence) or
            (clearfake.get("is_clearfake") and (valid_url(clearfake.get("delivery_url")) or clearfake.get("smart_contract")))
        ):
            return None
        finding = {
            "scan_id": c["scan_id"], "domain": c.get("domain"), "url": c.get("url"),
            "source": c.get("source", "urlscan.io"), "status": c.get("status"),
            "report_url": c.get("report_url"), "first_seen": c.get("first_seen") or c.get("time"),
            "is_clearfake": clearfake.get("is_clearfake", False),
            "is_cfmd": cfmd.get("is_cfmd", False), "is_mshta": mshta.get("is_mshta", False),
            "cfmd_lure": cfmd.get("lure_type"), "smart_contract": clearfake.get("smart_contract"),
            "method_hash": clearfake.get("method_hash"),
            "live_c2_url": clearfake.get("live_c2_url"), "delivery_url": clearfake.get("delivery_url"),
            "url_evidence": url_evidence,
        }
        return finding if indicators_for_scan(finding) else None
    except Exception as e:
        print(f"[!] Analysis failed for {c.get('scan_id')}: {e}")
        return None


def register_techniques(finding):
    domain = finding.get("domain")
    if finding.get("smart_contract"):
        sc = finding["smart_contract"]
        method = finding.get("method_hash") or "unknown"
        DetectionCatalog.register_technique(
            tech_id=f"contract_{sc.lower()[:10]}_{method}", category="Blockchain C2",
            name=f"Smart Contract Instance: {sc[:12]}...",
            signature=f"Contract: {sc} (Method: {method})", sample=domain,
            description=f"Observed ClearFake contract; resolved URL: {finding.get('live_c2_url')}.")
    if finding.get("is_mshta"):
        DetectionCatalog.register_technique(
            tech_id="mshta_activex_dropper", category="Execution Vector",
            name="MSHTA / ActiveXObject Stream Dropper",
            signature="mshta \"javascript:var x=new ActiveXObject('MSXML2.XMLHTTP')...\"",
            sample=domain,
            description="Uses MSXML2.XMLHTTP to download a remote file and ADODB.Stream to write it.")
    if finding.get("is_cfmd"):
        lure = finding.get("cfmd_lure") or "Verification Dialog"
        tech_id = f"cfmd_{lure.lower().replace(' ', '_').replace('/', '_').replace('(', '').replace(')', '')}"
        DetectionCatalog.register_technique(
            tech_id=tech_id, category="Social Engineering Lure", name=f"ClickFix Lure: {lure}",
            signature=f"Lure: {lure}", sample=domain,
            description="Observed lure with an extracted URL in the rendered scan.")


def parse_window_argument(value: str) -> int:
    """CLI accepts minutes for backwards compatibility or an explicit hour suffix."""
    hours = value.endswith("h")
    amount = value[:-1] if hours else value
    if not amount.isdecimal() or int(amount) <= 0:
        raise ValueError("Search window must be a positive integer in minutes or hours (e.g. 180 or 3h)")
    return int(amount) * (60 if hours else 1)


def run_pipeline(time_window_minutes: int = 1440):
    if time_window_minutes <= 0:
        raise ValueError("time_window_minutes must be positive")
    print(f"[*] Starting ClickFix Hunting Pipeline ({time_window_minutes}m search window)...")
    scans = load_database(SCANS_FILE)
    db = load_database(DATABASE_FILE)
    if db and not scans:
        raise RuntimeError("Legacy data detected. Run: python scripts/migrate_iocs.py")
    candidates = get_recent_candidates(time_window_minutes=time_window_minutes) + fetch_urlhaus_recent(
        limit=150, time_window_minutes=time_window_minutes)
    candidates.sort(key=lambda x: str(x.get("time") or x.get("first_seen") or ""))
    pending = {c["scan_id"]: c for c in candidates if c["scan_id"] not in scans}
    print(f"[*] Analyzing {len(pending)} new scans with 8 workers...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        findings = list(executor.map(analyze_candidate, pending.values()))
    observed_keys = set()
    new_iocs = []
    times = []
    for finding in findings:
        if not finding:
            continue
        scans[finding["scan_id"]] = compact_scan(finding)
        new_iocs.extend(merge_scan(db, finding))
        observed_keys.update(f"{kind}|{value}" for kind, value, _ in indicators_for_scan(finding))
        when = observed_at(finding.get("first_seen"))
        if when:
            times.append(when)
        register_techniques(finding)
    if any(findings):
        save_database(SCANS_FILE, scans)
        save_database(DATABASE_FILE, db)
        update_domains_list(db)
        latest = max(times).isoformat().replace("+00:00", "Z") if times else "unknown"
        observed = [db[key] for key in observed_keys]
        generate_markdown_report(observed, latest)
        export_to_daily_csv(observed)
    print(f"[+] Done: {sum(bool(f) for f in findings)} scans, {len(new_iocs)} new IOCs.")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 2:
        raise SystemExit("Usage: python main.py [MINUTES|HOURS_WITH_h_SUFFIX]")
    try:
        window = parse_window_argument(sys.argv[1]) if len(sys.argv) == 2 else 1440
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    run_pipeline(time_window_minutes=window)
