import os
import requests
import json
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("URLSCAN_API_KEY")
HEADERS = {
    "API-Key": API_KEY,
    "Content-Type": "application/json"
}

def inspect_scan(scan_id: str):
    url = f"https://urlscan.io/api/v1/result/{scan_id}/"
    resp = requests.get(url, headers=HEADERS)
    if resp.status_code != 200:
        print(f"Error {resp.status_code}: {resp.text}")
        return None
    data = resp.json()
    
    # Save a copy to inspect structure
    with open("data/sample_scan.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        
    print(f"[+] Scan details saved to data/sample_scan.json")
    
    # Check verdicts
    verdicts = data.get("verdicts", {})
    print(f"[*] Verdicts: {json.dumps(verdicts, indent=2)}")
    
    # Check page info
    page = data.get("page", {})
    print(f"[*] Page URL: {page.get('url')}")
    print(f"[*] Page Title: {page.get('title')}")
    print(f"[*] Page Domain: {page.get('domain')}")
    
    # Check requests/scripts for payload traces
    requests_list = data.get("data", {}).get("requests", [])
    print(f"[*] Total HTTP requests made: {len(requests_list)}")
    for req in requests_list:
        req_url = req.get("response", {}).get("response", {}).get("url", "")
        if any(ext in req_url.lower() for ext in [".dat", ".txt", ".ps1", ".sh", "curl", "b64", "cdn", "raw"]):
            print(f"    -> Suspicious request: {req_url}")

if __name__ == "__main__":
    # Test with the fresh scan found
    inspect_scan("01a0d980-cbce-7238-a47d-e2023785a21a")
