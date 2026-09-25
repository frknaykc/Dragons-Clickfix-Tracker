import os
import requests
import time
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

def search_scans(query: str, size: int = 15):
    """Searches urlscan.io for recent scans matching query"""
    url = f"https://urlscan.io/api/v1/search/?q={query}&size={size}"
    try:
        resp = requests.get(url, headers=HEADERS, timeout=10)
        if resp.status_code == 200:
            return resp.json().get("results", [])
        elif resp.status_code == 429:
            print("[!] Rate limited by urlscan.io, waiting...")
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

def get_recent_candidates():
    """
    Gathers fresh candidate scans from high-yield ClickFix hunting queries.
    Deduplicates by scan UUID and filters out benign whitelisted domains.
    """
    queries = [
        'task.tags:"@clickfixhunter"',
        'task.tags:"clickfix"',
        'page.text:("Download for macOS" AND "Terminal")'
    ]

    candidates = {}
    for q in queries:
        print(f"[*] Querying: {q}...")
        results = search_scans(q, size=10)
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
