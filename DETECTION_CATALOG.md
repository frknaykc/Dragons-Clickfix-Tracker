# 📘 Detection Techniques & Pattern Catalog
**Last Updated:** `2026-10-02 01:36:17 UTC`

This catalog tracks every unique hunting query, obfuscation technique, C2 mechanism, and lure pattern observed by ClickFix-Tracker. Use this catalog to inspect newly evolving threat behaviors and write targeted decoders.

| Category | Technique Name | Signature / Pattern | First Seen | Sample |
| :--- | :--- | :--- | :--- | :--- |
| **Hunting Trigger** | URLScan Telemetry Tag: @clickfixhunter | `task.tags:"@clickfixhunter"` | `2026-09-25` | `ucc-tr.com` |
| **Obfuscation** | ClearFake Double-XOR + Base64 JS Loader | `fromCharCode(arr[i] ^ key1) -> atob -> charCodeAt(i) ^ key2 -> (new Function(code))()` | `2026-09-25` | `ucc-tr.com` |
| **Blockchain C2** | Polygon (MATIC) Smart Contract eth_call C2 Resolver | `eth_call to 0x... with 4-byte method hash (e.g. 0xb68d1809)` | `2026-09-25` | `0xB6bC9e1D0b2fB96Ab7C47E04Cb0BE477410bC1f2` |
| **Payload Encoding** | Base64 Universal HTTP/HTTPS Signature | `aHR0cHM6Ly (https://) or aHR0cDov (http://)` | `2026-09-25` | `Various` |
| **Social Engineering** | macOS Spotlight + Terminal Installation Lure | `Command (⌘) + Space -> Terminal -> curl -s ... | bash` | `2026-09-25` | `fileonyxzone.com / filecobaltgate.com` |
| **Blockchain C2** | Smart Contract Instance: 0xB6bC9e1D0b... | `Contract: 0xB6bC9e1D0b2fB96Ab7C47E04Cb0BE477410bC1f2 (Method: 0xb68d1809)` | `2026-09-25` | `ucc-tr.com` |
| **Blockchain C2** | Smart Contract Instance: 0xB6bC9e1D0b... | `Contract: 0xB6bC9e1D0b2fB96Ab7C47E04Cb0BE477410bC1f2 (Method: None)` | `2026-09-25` | `uberrichinfatcity.com` |
| **Social Engineering Lure** | ClickFix Lure: ClickFix Verification Dialog | `Framework: __cfmdCaptcha (WUA Token: None)` | `2026-10-02` | `grupoartek.com` |
| **Social Engineering Lure** | ClickFix Lure: Fake Microsoft Account Verification | `Framework: __cfmdCaptcha (WUA Token: 22ab8f9767)` | `2026-10-02` | `cgageauthor.com` |

## 🔍 Technique Details

### URLScan Telemetry Tag: @clickfixhunter (`query_clickfixhunter_tag`)
* **Category:** Hunting Trigger
* **Pattern / Signature:** `task.tags:"@clickfixhunter"`
* **First Observed:** 2026-09-25
* **Sample Indicator:** `ucc-tr.com`
* **Description & Hunting Action:** Public threat hunting telemetry tracking in-the-wild compromised WordPress/corporate sites serving ClickFix.

### ClearFake Double-XOR + Base64 JS Loader (`clearfake_double_xor`)
* **Category:** Obfuscation
* **Pattern / Signature:** `fromCharCode(arr[i] ^ key1) -> atob -> charCodeAt(i) ^ key2 -> (new Function(code))()`
* **First Observed:** 2026-09-25
* **Sample Indicator:** `ucc-tr.com`
* **Description & Hunting Action:** Injected JavaScript unpacks via double XOR operations with dynamically assigned integer keys to evade static AV.

### Polygon (MATIC) Smart Contract eth_call C2 Resolver (`polygon_smart_contract_c2`)
* **Category:** Blockchain C2
* **Pattern / Signature:** `eth_call to 0x... with 4-byte method hash (e.g. 0xb68d1809)`
* **First Observed:** 2026-09-25
* **Sample Indicator:** `0xB6bC9e1D0b2fB96Ab7C47E04Cb0BE477410bC1f2`
* **Description & Hunting Action:** Threat actors host the current active C2/TDS domain in EVM smart contract storage to survive domain take-downs.

### Base64 Universal HTTP/HTTPS Signature (`base64_url_signature`)
* **Category:** Payload Encoding
* **Pattern / Signature:** `aHR0cHM6Ly (https://) or aHR0cDov (http://)`
* **First Observed:** 2026-09-25
* **Sample Indicator:** `Various`
* **Description & Hunting Action:** Extracts raw download/payload links obfuscated in base64 within scripts, clipboard buffers, or HTML elements.

### macOS Spotlight + Terminal Installation Lure (`macos_bash_terminal_lure`)
* **Category:** Social Engineering
* **Pattern / Signature:** `Command (⌘) + Space -> Terminal -> curl -s ... | bash`
* **First Observed:** 2026-09-25
* **Sample Indicator:** `fileonyxzone.com / filecobaltgate.com`
* **Description & Hunting Action:** Fakes GitHub/software release page, instructing Mac users to run curl piped into bash to infect macOS.

### Smart Contract Instance: 0xB6bC9e1D0b... (`contract_0xb6bc9e1d_0xb68d1809`)
* **Category:** Blockchain C2
* **Pattern / Signature:** `Contract: 0xB6bC9e1D0b2fB96Ab7C47E04Cb0BE477410bC1f2 (Method: 0xb68d1809)`
* **First Observed:** 2026-09-25
* **Sample Indicator:** `ucc-tr.com`
* **Description & Hunting Action:** Active Polygon smart contract observed resolving live C2 https://idcool.codes.

### Smart Contract Instance: 0xB6bC9e1D0b... (`contract_0xb6bc9e1d_None`)
* **Category:** Blockchain C2
* **Pattern / Signature:** `Contract: 0xB6bC9e1D0b2fB96Ab7C47E04Cb0BE477410bC1f2 (Method: None)`
* **First Observed:** 2026-09-25
* **Sample Indicator:** `uberrichinfatcity.com`
* **Description & Hunting Action:** Active Polygon smart contract observed resolving live C2 None.

### ClickFix Lure: ClickFix Verification Dialog (`cfmd_clickfix_verification_dialog`)
* **Category:** Social Engineering Lure
* **Pattern / Signature:** `Framework: __cfmdCaptcha (WUA Token: None)`
* **First Observed:** 2026-10-02
* **Sample Indicator:** `grupoartek.com`
* **Description & Hunting Action:** PowerShell WUA Stager connecting to https://securityalertcaptchacheck.com.

### ClickFix Lure: Fake Microsoft Account Verification (`cfmd_fake_microsoft_account_verification`)
* **Category:** Social Engineering Lure
* **Pattern / Signature:** `Framework: __cfmdCaptcha (WUA Token: 22ab8f9767)`
* **First Observed:** 2026-10-02
* **Sample Indicator:** `cgageauthor.com`
* **Description & Hunting Action:** PowerShell WUA Stager connecting to https://cloudeccentric.cc.
