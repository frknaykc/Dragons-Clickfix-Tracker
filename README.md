# 🎯 ClickFix & ClearFake Automated Threat Tracker

An automated Cyber Threat Intelligence (CTI) engine that proactively tracks, deobfuscates, and archives **ClickFix** and **ClearFake** campaigns in the wild.

## 🚀 Key Features

* **Heuristic Hunting:** Continuously identifies active lure and compromised landing pages via [urlscan.io](https://urlscan.io) search telemetry.
* **Double-XOR JavaScript Deobfuscator:** Reverses multi-stage encoded and obfuscated JS loaders automatically.
* **Smart Contract C2 Resolver:** Intercepts decentralized C2 architectures by querying Polygon (MATIC) blockchain RPCs using `eth_call` to resolve dynamic C2/TDS delivery domains.
* **Base64 & PowerShell Extraction:** Decodes stage-2 payload URLs (`aHR0...`, PowerShell `-enc`, bash `curl | sh`).
* **Auto Defanging:** Generates safe, defanged indicators (`hxxps://`, `[.]`) preventing link clicks and platform abuse filters.
* **Zero-Touch CI/CD:** Runs automatically 24/7 via GitHub Actions.

---

## 📊 Live Feeds

* 📄 **[LATEST_REPORT.md](LATEST_REPORT.md):** Human-readable threat intelligence briefing of latest observed campaigns.
* 🛡️ **[data/domains.txt](data/domains.txt):** Clean, deduplicated domain list ready for ingestion into Pi-hole, AdGuard Home, DNS firewalls, and proxy blocklists.
* 📈 **[data/daily/](data/daily/):** Daily structured CSV exports (`YYYY-MM-DD.csv`) formatted with timestamp, type, indicator, threat type, and reference.
* 📘 **[DETECTION_CATALOG.md](DETECTION_CATALOG.md):** Catalog of observed obfuscation methods, smart contract C2s, and attack lures.
* 📦 **[data/iocs.json](data/iocs.json):** Full structured database containing scan UUIDs, timestamps, IPs, ASNs, contracts, and decoded payloads.

---

## 🛠️ Local Usage

### 1. Clone & Setup
```bash
git clone https://github.com/frknaykc/Dragons-Clickfix-Tracker.git
cd Dragons-Clickfix-Tracker
pip install -r requirements.txt
```

### 2. Configure Environment
Copy `.env.example` to `.env` and add your free `urlscan.io` API key:
```env
URLSCAN_API_KEY=your_urlscan_api_key_here
```

### 3. Run Pipeline
```bash
python main.py
```

---

## 🤖 24/7 GitHub Actions Setup

To run this pipeline autonomously:
1. Push this repository to GitHub.
2. Go to **Settings > Secrets and variables > Actions**.
3. Add a new repository secret:
   * Name: `URLSCAN_API_KEY`
   * Value: `Your urlscan.io API Key`
4. The workflow in `.github/workflows/hunter.yml` will run every 20 minutes, scan for new campaigns, deobfuscate payloads, and automatically commit the updated feeds!

---
*Disclaimer: All indicators are provided strictly for defensive research, threat hunting, and educational purposes.*
