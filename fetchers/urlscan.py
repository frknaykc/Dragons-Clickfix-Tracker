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

SESSION = requests.Session()
SESSION.headers.update(HEADERS)

def get_known_c2_domains(database_file: str = "data/iocs.json") -> list[str]:
    """
    Extracts all resolved live C2 domains from the local database
    plus live blockchain smart contracts to dynamically pivot and hunt.
    """
    c2s = set()

    # 1. Check typed local indicators
    if os.path.exists(database_file):
        try:
            with open(database_file, "r", encoding="utf-8") as f:
                db = json.load(f)
                for item in db.values():
                    if item.get("type") == "c2_host" and item.get("value"):
                        c2s.add(item["value"])
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

def search_scans(query: str, size: int = 100, max_retries: int = 3):
    """Searches urlscan.io for recent scans matching query with retry logic"""
    url = f"https://urlscan.io/api/v1/search/?q={query}&size={size}"
    for attempt in range(max_retries):
        try:
            resp = SESSION.get(url, timeout=12)
            if resp.status_code == 200:
                return resp.json().get("results", [])
            elif resp.status_code == 429:
                wait_time = 4 * (attempt + 1)
                print(f"[!] Rate limited by urlscan.io, waiting {wait_time}s (attempt {attempt+1}/{max_retries})...")
                time.sleep(wait_time)
            else:
                break
        except Exception as e:
            if attempt == max_retries - 1:
                print(f"[!] Error querying urlscan: {e}")
            time.sleep(2)
    return []

def get_dom(dom_url: str, max_retries: int = 2) -> str:
    """Downloads rendered HTML DOM for analysis with retry logic"""
    for attempt in range(max_retries):
        try:
            resp = SESSION.get(dom_url, timeout=15)
            if resp.status_code == 200:
                return resp.text
            elif resp.status_code == 429:
                time.sleep(3)
        except Exception:
            time.sleep(1)
    return ""

def get_recent_candidates(time_window_minutes: int = 1440):
    """
    Gathers candidate scans using:
    1. Global hunting tags (@clickfixhunter, clickfix, clearfake, etherhiding, threatfox)
    2. Heuristic text lures (Meeting/Audio fix, Browser update, macOS Spotlight, Windows Run, Win+X)
    3. Clipboard injection signatures (writeText + powershell/curl/mshta)
    4. Dynamic C2 pivoting (automatically searching for any domain contacting known C2s)
    Default window: 1440m (24h) for fresh campaigns.
    """
    time_filter = f"date:>now-{time_window_minutes}m AND " if time_window_minutes else ""

    queries = [
        f'{time_filter}(task.tags:"@clickfixhunter" OR task.tags:"clickfix" OR task.tags:"clearfake" OR task.tags:"etherhiding" OR (task.tags:"threatfox" AND task.tags:"clickfix"))',
        f'{time_filter}(page.text:("Download for macOS" AND "Terminal") OR page.text:("Press Windows Key + R"))',
        f'{time_filter}(page.text:("To verify your request" AND "PowerShell") OR page.text:("Verify it\'s you" AND "PowerShell") OR page.text:("Confirm this sign-in"))',
        f'{time_filter}(page.text:("open Spotlight" AND "Terminal") OR page.text:("secure.gateway" AND "Verify your identity"))',
        f'{time_filter}(page.text:("Windows Security" AND "Human verification required") OR page.text:("MSXML2.XMLHTTP" AND "ActiveXObject"))',
        f'{time_filter}(page.text:("claude.com" AND "Performing security verification") OR page.text:("Gateway Verification" AND "Challenge Response ID"))',
        f'{time_filter}(page.text:("Microphone not working" OR "Fix microphone" OR "audio issue") AND page.text:("PowerShell" OR "Terminal"))',
        f'{time_filter}(page.text:("Update Chrome" OR "Update your browser" OR "Outdated browser") AND page.text:("PowerShell" OR "Terminal" OR "Run"))',
        f'{time_filter}(page.text:("writeText" AND "powershell") OR page.text:("writeText" AND "curl") OR page.text:("writeText" AND "mshta"))',
        f'{time_filter}(page.url:("/verify-page.js" OR "/KL.bat" OR "/KL.zip" OR "claudedevz.net" OR "cocuktekstil.com" OR "acmaturaky.cz"))'
    ]

    # Dynamically pivot on active C2 domains extracted from smart contracts / deobfuscation
    c2_domains = get_known_c2_domains()
    if c2_domains:
        for i in range(0, min(len(c2_domains), 40), 5):
            batch = c2_domains[i:i+5]
            c2_part = " OR ".join([f'"{d}"' for d in batch])
            queries.append(f'{time_filter}domain:({c2_part})')

    candidates = {}
    for q in queries:
        print(f"[*] Querying (Window: {time_window_minutes}m): {q[:95]}...")
        results = search_scans(q, size=100)
        print(f"    -> Found {len(results)} scans.")
        for r in results:
            scan_id = r.get("_id")
            page = r.get("page", {})
            domain = page.get("domain", "")

            # Keep the scanned URL, including shared hosts: classification happens at IOC extraction.
            if not domain:
                continue

            uuid = r.get("task", {}).get("uuid") or scan_id
            if uuid and uuid not in candidates:
                candidates[uuid] = {
                    "scan_id": uuid,
                    "url": page.get("url"),
                    "domain": domain,
                    "dom_url": f"https://urlscan.io/dom/{uuid}/",
                    "report_url": f"https://urlscan.io/result/{uuid}/",
                    "time": r.get("task", {}).get("time")
                }
        time.sleep(1) # Courtesy pause between queries

    return list(candidates.values())
