import os
import requests
import time
import json
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("URLSCAN_API_KEY")
HEADERS = {
    "API-Key": API_KEY,
    "Content-Type": "application/json"
}

WHITELIST_DOMAINS = {
    "github.com", "apple.com", "microsoft.com", "google.com", 
    "brew.sh", "docker.com", "rustup.rs", "cloudflare.com",
    "gitlab.com", "bitbucket.org", "mozilla.org", "stackoverflow.com"
}

def get_known_c2_domains(database_file: str = "data/iocs.json") -> list[str]:
    """
    Extracts all resolved live C2 domains from the local database
    plus live blockchain smart contracts to dynamically pivot and hunt.
    """
    c2s = {"idcool.codes", "entry-verifed-cdn.codes", "makeverizyjar.info"}
    
    # 1. Check local database
    if os.path.exists(database_file):
        try:
            with open(database_file, "r", encoding="utf-8") as f:
                db = json.load(f)
                for item in db.values():
                    c2_url = item.get("live_c2_url")
                    if c2_url:
                        clean_dom = c2_url.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].strip()
                        if clean_dom and "." in clean_dom:
                            c2s.add(clean_dom)
        except Exception:
            pass

    # 2. Query active Polygon Smart Contract directly for current live C2
    try:
        from core.decoder import PayloadDecoder
        live_sc_c2 = PayloadDecoder.resolve_blockchain_c2("0xB6bC9e1D0b2fB96Ab7C47E04Cb0BE477410bC1f2", "0xb68d1809")
        if live_sc_c2:
            sc_dom = live_sc_c2.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].strip()
            if sc_dom and "." in sc_dom:
                c2s.add(sc_dom)
    except Exception:
        pass

    return list(c2s)

def search_scans(query: str, size: int = 100):
    """Searches urlscan.io for recent scans matching query"""
    url = f"https://urlscan.io/api/v1/search/?q={query}&size={size}"
    try:
        resp = requests.get(url, headers=HEADERS, timeout=12)
        if resp.status_code == 200:
            return resp.json().get("results", [])
        elif resp.status_code == 429:
            print("[!] Rate limited by urlscan.io, waiting 5 seconds...")
            time.sleep(5)
    except Exception as e:
        print(f"[!] Error querying urlscan: {e}")
    return []

def get_dom(dom_url: str) -> str:
    """Downloads rendered HTML DOM for analysis"""
    try:
        resp = requests.get(dom_url, headers=HEADERS, timeout=15)
        if resp.status_code == 200:
            return resp.text
    except Exception:
        pass
    return ""

def get_recent_candidates(time_window_minutes: int = 4320):
    """
    Gathers candidate scans using:
    1. Global hunting tags (@clickfixhunter, clickfix)
    2. Heuristic text lures (macOS Terminal, Windows Run)
    3. Dynamic C2 pivoting (automatically searching for any domain contacting known C2s)
    """
    time_filter = f"date:>now-{time_window_minutes}m AND " if time_window_minutes else ""

    queries = [
        f'{time_filter}(task.tags:"@clickfixhunter" OR task.tags:"clickfix")',
        f'{time_filter}(page.text:("Download for macOS" AND "Terminal") OR page.text:("Press Windows Key + R"))'
    ]

    # Dynamically pivot on active C2 domains extracted from smart contracts / deobfuscation
    c2_domains = get_known_c2_domains()
    if c2_domains:
        for i in range(0, min(len(c2_domains), 20), 5):
            batch = c2_domains[i:i+5]
            c2_part = " OR ".join([f'"{d}"' for d in batch])
            queries.append(f'{time_filter}domain:({c2_part})')

    candidates = {}
    for q in queries:
        print(f"[*] Querying (Window: {time_window_minutes}m): {q}...")
        results = search_scans(q, size=100)
        print(f"    -> Found {len(results)} scans.")
        for r in results:
            scan_id = r.get("_id")
            page = r.get("page", {})
            domain = page.get("domain", "")

            # Filter whitelist
            if any(w in domain.lower() for w in WHITELIST_DOMAINS):
                continue

            uuid = r.get("task", {}).get("uuid") or scan_id
            if uuid and uuid not in candidates:
                candidates[uuid] = {
                    "scan_id": uuid,
                    "url": page.get("url"),
                    "domain": domain,
                    "ip": page.get("ip"),
                    "asn": page.get("asnname"),
                    "country": page.get("country"),
                    "dom_url": f"https://urlscan.io/dom/{uuid}/",
                    "report_url": f"https://urlscan.io/result/{uuid}/",
                    "time": r.get("task", {}).get("time")
                }
        time.sleep(1) # Courtesy pause between queries

    return list(candidates.values())
