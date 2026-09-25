import os
from datetime import datetime, timezone
from utils.defang import defang_domain, defang_url, defang_ip

TWEETS_FILE = "TWEETS_TO_POST.md"

def format_campaign_cluster_tweet(findings: list[dict]) -> str:
    """
    Groups all compromised hosts belonging to the same ClearFake / ClickFix cluster
    into a single comprehensive, high-impact CTI tweet.
    """
    if not findings:
        return ""

    # Group hosts
    hosts_lines = []
    seen_domains = set()

    smart_contract = None
    method_hash = None
    c2_url = None
    delivery_url = None
    sample_ref = None

    for f in findings:
        dom = f.get("domain")
        if dom and dom not in seen_domains:
            seen_domains.add(dom)
            def_dom = defang_domain(dom)
            ip_str = defang_ip(f.get("ip", ""))
            asn = f.get("asn", "")
            # Shorten ASN if too long
            asn_short = asn.split(" - ")[0] if " - " in asn else asn
            if ip_str:
                hosts_lines.append(f"• {def_dom} (IP: {ip_str})")
            else:
                hosts_lines.append(f"• {def_dom}")

        if not smart_contract and f.get("smart_contract"):
            smart_contract = f.get("smart_contract")
            method_hash = f.get("method_hash") or "0xb68d1809"

        if not c2_url and f.get("live_c2_url"):
            c2_url = defang_url(f.get("live_c2_url"))

        if not delivery_url and f.get("delivery_url"):
            delivery_url = defang_url(f.get("delivery_url"))

        if not sample_ref and f.get("report_url"):
            sample_ref = f.get("report_url")

    hosts_text = "\n".join(hosts_lines[:10]) # Top 10 hosts in cluster

    long_post = f"""👀 ClearFake / ClickFix (Smart Contract C2) — Observed IOCs

[Compromised Injected Hosts (Initial Access)]
{hosts_text}

[Injected Script Obfuscation Layer]
• In-line Double-XOR + Base64 JavaScript Loader
• Function: Queries decentralized blockchain RPC to fetch active C2

[Decentralized Blockchain C2 Infrastructure (Polygon MATIC)]
• Smart Contract: {smart_contract or '0xB6bC9e1D0b2fB96Ab7C47E04Cb0BE477410bC1f2'}
• Method Hash: {method_hash or '0xb68d1809'}
• Public RPC: polygon-bor-rpc.publicnode[.]com | 1rpc[.]io/matic

[Resolved Live C2 / TDS Infrastructure]
• {c2_url or 'hxxps://idcool[.]codes'}

[Observed TDS / Staging Delivery URLs]
• {delivery_url or 'N/A'}

#ClickFix #ClearFake #ThreatIntel #Malware #CyberSecurity #IOC"""

    return long_post

def save_tweet_draft(findings: list[dict]):
    """
    Generates a consolidated campaign tweet draft with all compromised hosts.
    """
    if not findings:
        return

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    campaign_tweet = format_campaign_cluster_tweet(findings)

    existing_content = ""
    if os.path.exists(TWEETS_FILE):
        try:
            with open(TWEETS_FILE, "r", encoding="utf-8") as f:
                existing_content = f.read()
        except Exception:
            pass

    new_content = f"""## 📢 Consolidated Campaign Draft — Generated at `{now_str}`

> 💡 **Ready for X Premium / LinkedIn:** Click the Copy icon on the top right to post.

```text
{campaign_tweet.strip()}
```

---
""" + existing_content

    with open(TWEETS_FILE, "w", encoding="utf-8") as f:
        f.write(new_content)

    print(f"[🐦] Generated consolidated campaign tweet in {TWEETS_FILE}")
    send_macos_notification("ClickFix Threat Hunter", "Tüm siteleri içeren toplu Tweet taslağı hazır!")

def send_macos_notification(title: str, message: str):
    try:
        os.system(f"""osascript -e 'display notification "{message}" with title "{title}"'""")
    except Exception:
        pass
