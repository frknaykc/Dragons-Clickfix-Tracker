import os
from datetime import datetime, timezone
from utils.defang import defang_domain, defang_url, defang_ip

TWEETS_FILE = "TWEETS_TO_POST.md"

def format_tweet_thread(finding: dict) -> str:
    """
    Formats a structured finding into a ready-to-copy Twitter/X post.
    Includes both Long-form (X Premium) and Split Thread (Standard 280-char) formats.
    """
    domain = defang_domain(finding.get("domain", ""))
    ip = defang_ip(finding.get("ip", ""))
    asn = finding.get("asn", "Unknown")
    sc = finding.get("smart_contract")
    method = finding.get("method_hash", "N/A")
    c2_url = defang_url(finding.get("live_c2_url", ""))
    delivery_url = defang_url(finding.get("delivery_url", ""))
    ref = finding.get("report_url", "")

    # 1. Long-form Post (Ideal for X Premium or LinkedIn)
    long_post = f"""👀 ClearFake / ClickFix (Smart Contract C2) — Observed IOCs

[Compromised Host (Initial Access)]
• {domain} (IP: {ip} | ASN: {asn})

[Injected Obfuscation Layer]
• In-line Double-XOR + Base64 JavaScript Loader
• Function: Queries decentralized blockchain RPC to fetch active C2

[Decentralized Blockchain C2 (Polygon MATIC)]
• Smart Contract: {sc or 'N/A'}
• Method Hash: {method}

[Resolved Live C2 / TDS Infrastructure]
• {c2_url or 'N/A'}

[Observed TDS / Staging Delivery URLs]
• {delivery_url or 'N/A'}

Ref: {ref}
#ClickFix #ClearFake #ThreatIntel #Malware #CyberSecurity #IOC"""

    # 2. Standard 280-char Split Thread format
    tweet_1 = f"""🚨 New ClearFake / #ClickFix Cluster Observed!

[Compromised Landing]: {domain}
[IP]: {ip}

Injected script uses Double-XOR JS calling Polygon smart contract ({sc[:10]}...) to fetch dynamic C2.

Details below 🧵👇
#ThreatIntel #IOC"""

    tweet_2 = f"""🔗 ClearFake C2 Infrastructure Resolved:

[Smart Contract]: {sc}
[Method]: {method}
[Resolved C2]: {c2_url}
[Delivery URL]: {delivery_url}

Ref: {ref}
#Malware #CyberSecurity"""

    return long_post, [tweet_1, tweet_2]

def save_tweet_draft(findings: list[dict]):
    """
    Appends newly generated tweet drafts to TWEETS_TO_POST.md.
    Only drafts tweets for high-fidelity findings with resolved C2 or unique indicators.
    """
    if not findings:
        return

    # Filter findings that have a fully resolved C2 URL or novel finding
    seen_keys = set()
    high_value_findings = []
    for f in findings:
        c2 = f.get("live_c2_url")
        if c2:
            key = (f.get("smart_contract"), c2)
            if key not in seen_keys:
                seen_keys.add(key)
                high_value_findings.append(f)

    if not high_value_findings:
        return

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    existing_content = ""
    if os.path.exists(TWEETS_FILE):
        try:
            with open(TWEETS_FILE, "r", encoding="utf-8") as f:
                existing_content = f.read()
        except Exception:
            pass

    new_entries = [
        f"## 📢 High-Confidence Campaign Draft — Generated at `{now_str}`\n",
        "> 💡 **How to use:** Click the Copy icon on the top right of the code box and paste directly into Twitter/X.\n"
    ]

    for item in high_value_findings:
        long_post, thread = format_tweet_thread(item)
        new_entries.append("### Option A: Long-form Tweet (X Premium / LinkedIn)\n")
        new_entries.append("```text\n" + long_post.strip() + "\n```\n")

        new_entries.append("### Option B: Standard 280-Char Thread (Regular X Accounts)\n")
        for i, t in enumerate(thread, 1):
            new_entries.append(f"**Tweet {i}:** ({len(t)} chars)\n```text\n{t.strip()}\n```\n")

        new_entries.append("---\n")

    full_output = "\n".join(new_entries) + "\n" + existing_content

    with open(TWEETS_FILE, "w", encoding="utf-8") as f:
        f.write(full_output)

    print(f"[🐦] Generated fresh tweet drafts in {TWEETS_FILE}")
    send_macos_notification("ClickFix Threat Hunter", f"Yeni Tweet taslağı {TWEETS_FILE} dosyasına eklendi!")

def send_macos_notification(title: str, message: str):
    """Sends a native macOS desktop notification"""
    try:
        os.system(f"""osascript -e 'display notification "{message}" with title "{title}"'""")
    except Exception:
        pass
