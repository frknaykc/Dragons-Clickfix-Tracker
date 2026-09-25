import os
import csv
from datetime import datetime, timezone
from utils.defang import defang_domain, defang_url, defang_ip

DAILY_DIR = "data/daily"

CSV_HEADERS = [
    "timestamp",
    "type",
    "indicator",
    "threat_type",
    "detection_method",
    "first_seen",
    "reference"
]

def ensure_daily_dir():
    os.makedirs(DAILY_DIR, exist_ok=True)

def export_to_daily_csv(findings: list[dict]):
    """
    Appends newly observed indicators into daily CSV files (YYYY-MM-DD.csv).
    Avoids duplicate entries within the file.
    """
    if not findings:
        return

    ensure_daily_dir()
    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    csv_file = os.path.join(DAILY_DIR, f"{today_str}.csv")

    existing_indicators = set()
    file_exists = os.path.exists(csv_file)

    if file_exists:
        try:
            with open(csv_file, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    existing_indicators.add((row.get("type"), row.get("indicator")))
        except Exception:
            pass

    rows_to_write = []
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    for f in findings:
        ref = f.get("report_url") or f.get("url")
        first_seen = f.get("first_seen", now_str)

        # 1. Compromised / Landing Domain
        if f.get("domain"):
            ind = defang_domain(f["domain"])
            if ("domain", ind) not in existing_indicators:
                rows_to_write.append({
                    "timestamp": now_str,
                    "type": "domain",
                    "indicator": ind,
                    "threat_type": "Compromised Host / Lure Page",
                    "detection_method": "urlscan telemetry",
                    "first_seen": first_seen,
                    "reference": ref
                })
                existing_indicators.add(("domain", ind))

        # 2. IP Address
        if f.get("ip"):
            ind_ip = defang_ip(f["ip"])
            if ("ip", ind_ip) not in existing_indicators:
                rows_to_write.append({
                    "timestamp": now_str,
                    "type": "ip",
                    "indicator": ind_ip,
                    "threat_type": "Injected Host IP",
                    "detection_method": f"ASN: {f.get('asn', 'Unknown')}",
                    "first_seen": first_seen,
                    "reference": ref
                })
                existing_indicators.add(("ip", ind_ip))

        # 3. Smart Contract C2
        if f.get("smart_contract"):
            sc = f["smart_contract"]
            method = f.get("method_hash", "N/A")
            if ("smart_contract", sc) not in existing_indicators:
                rows_to_write.append({
                    "timestamp": now_str,
                    "type": "smart_contract",
                    "indicator": sc,
                    "threat_type": "Decentralized C2 (Polygon)",
                    "detection_method": f"ClearFake Double-XOR (Method: {method})",
                    "first_seen": first_seen,
                    "reference": f.get("domain")
                })
                existing_indicators.add(("smart_contract", sc))

        # 4. Resolved Live C2 URL / Domain
        if f.get("live_c2_url"):
            c2_url = defang_url(f["live_c2_url"])
            if ("c2_url", c2_url) not in existing_indicators:
                rows_to_write.append({
                    "timestamp": now_str,
                    "type": "c2_url",
                    "indicator": c2_url,
                    "threat_type": "Resolved ClearFake C2",
                    "detection_method": "Blockchain eth_call extraction",
                    "first_seen": first_seen,
                    "reference": f.get("domain")
                })
                existing_indicators.add(("c2_url", c2_url))

        # 5. Delivery TDS URL
        if f.get("delivery_url"):
            del_url = defang_url(f["delivery_url"])
            if ("delivery_url", del_url) not in existing_indicators:
                rows_to_write.append({
                    "timestamp": now_str,
                    "type": "delivery_url",
                    "indicator": del_url,
                    "threat_type": "TDS Staging Script",
                    "detection_method": "ClearFake Secret extraction",
                    "first_seen": first_seen,
                    "reference": f.get("domain")
                })
                existing_indicators.add(("delivery_url", del_url))

        # 6. Extracted Base64 / Payload URLs
        for pu in f.get("extracted_b64_urls", []):
            def_pu = defang_url(pu)
            if ("payload_url", def_pu) not in existing_indicators:
                rows_to_write.append({
                    "timestamp": now_str,
                    "type": "payload_url",
                    "indicator": def_pu,
                    "threat_type": "Second Stage Payload",
                    "detection_method": "Base64 / PowerShell decoding",
                    "first_seen": first_seen,
                    "reference": f.get("domain")
                })
                existing_indicators.add(("payload_url", def_pu))

    if rows_to_write:
        with open(csv_file, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
            if not file_exists or os.path.getsize(csv_file) == 0:
                writer.writeheader()
            writer.writerows(rows_to_write)
        print(f"[+] Exported {len(rows_to_write)} IOCs to {csv_file}")
