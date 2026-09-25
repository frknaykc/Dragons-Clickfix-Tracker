import os
import json
from datetime import datetime, timezone

CATALOG_JSON = "data/detection_catalog.json"
CATALOG_MD = "DETECTION_CATALOG.md"

DEFAULT_TECHNIQUES = [
    {
        "id": "query_clickfixhunter_tag",
        "category": "Hunting Trigger",
        "name": "URLScan Telemetry Tag: @clickfixhunter",
        "signature": "task.tags:\"@clickfixhunter\"",
        "first_observed": "2026-09-25",
        "sample_indicator": "ucc-tr.com",
        "description": "Public threat hunting telemetry tracking in-the-wild compromised WordPress/corporate sites serving ClickFix."
    },
    {
        "id": "clearfake_double_xor",
        "category": "Obfuscation",
        "name": "ClearFake Double-XOR + Base64 JS Loader",
        "signature": "fromCharCode(arr[i] ^ key1) -> atob -> charCodeAt(i) ^ key2 -> (new Function(code))()",
        "first_observed": "2026-09-25",
        "sample_indicator": "ucc-tr.com",
        "description": "Injected JavaScript unpacks via double XOR operations with dynamically assigned integer keys to evade static AV."
    },
    {
        "id": "polygon_smart_contract_c2",
        "category": "Blockchain C2",
        "name": "Polygon (MATIC) Smart Contract eth_call C2 Resolver",
        "signature": "eth_call to 0x... with 4-byte method hash (e.g. 0xb68d1809)",
        "first_observed": "2026-09-25",
        "sample_indicator": "0xB6bC9e1D0b2fB96Ab7C47E04Cb0BE477410bC1f2",
        "description": "Threat actors host the current active C2/TDS domain in EVM smart contract storage to survive domain take-downs."
    },
    {
        "id": "base64_url_signature",
        "category": "Payload Encoding",
        "name": "Base64 Universal HTTP/HTTPS Signature",
        "signature": "aHR0cHM6Ly (https://) or aHR0cDov (http://)",
        "first_observed": "2026-09-25",
        "sample_indicator": "Various",
        "description": "Extracts raw download/payload links obfuscated in base64 within scripts, clipboard buffers, or HTML elements."
    },
    {
        "id": "macos_bash_terminal_lure",
        "category": "Social Engineering",
        "name": "macOS Spotlight + Terminal Installation Lure",
        "signature": "Command (⌘) + Space -> Terminal -> curl -s ... | bash",
        "first_observed": "2026-09-25",
        "sample_indicator": "fileonyxzone.com / filecobaltgate.com",
        "description": "Fakes GitHub/software release page, instructing Mac users to run curl piped into bash to infect macOS."
    }
]

class DetectionCatalog:
    @staticmethod
    def load_catalog() -> list[dict]:
        if os.path.exists(CATALOG_JSON):
            try:
                with open(CATALOG_JSON, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return DEFAULT_TECHNIQUES.copy()

    @staticmethod
    def save_catalog(techniques: list[dict]):
        with open(CATALOG_JSON, "w", encoding="utf-8") as f:
            json.dump(techniques, f, indent=2, ensure_ascii=False)
        DetectionCatalog.generate_markdown(techniques)

    @staticmethod
    def register_technique(tech_id: str, category: str, name: str, signature: str, sample: str, description: str):
        """
        Registers a new detection method/pattern if it does not already exist.
        """
        techniques = DetectionCatalog.load_catalog()
        existing_ids = {t["id"] for t in techniques}

        if tech_id not in existing_ids:
            today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            entry = {
                "id": tech_id,
                "category": category,
                "name": name,
                "signature": signature,
                "first_observed": today_str,
                "sample_indicator": sample,
                "description": description
            }
            techniques.append(entry)
            DetectionCatalog.save_catalog(techniques)
            print(f"[🌟] NEW DETECTION TECHNIQUE CATALOGED: [{category}] {name}")
            return True
        return False

    @staticmethod
    def generate_markdown(techniques: list[dict]):
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        lines = [
            "# 📘 Detection Techniques & Pattern Catalog",
            f"**Last Updated:** `{now_str}`\n",
            "This catalog tracks every unique hunting query, obfuscation technique, C2 mechanism, and lure pattern observed by ClickFix-Tracker. Use this catalog to inspect newly evolving threat behaviors and write targeted decoders.\n",
            "| Category | Technique Name | Signature / Pattern | First Seen | Sample |",
            "| :--- | :--- | :--- | :--- | :--- |"
        ]

        for t in techniques:
            lines.append(f"| **{t['category']}** | {t['name']} | `{t['signature']}` | `{t['first_observed']}` | `{t['sample_indicator']}` |")

        lines.append("\n## 🔍 Technique Details\n")
        for t in techniques:
            lines.append(f"### {t['name']} (`{t['id']}`)")
            lines.append(f"* **Category:** {t['category']}")
            lines.append(f"* **Pattern / Signature:** `{t['signature']}`")
            lines.append(f"* **First Observed:** {t['first_observed']}")
            lines.append(f"* **Sample Indicator:** `{t['sample_indicator']}`")
            lines.append(f"* **Description & Hunting Action:** {t['description']}\n")

        with open(CATALOG_MD, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
