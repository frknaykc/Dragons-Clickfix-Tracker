# 📘 Detection Techniques & Pattern Catalog
**Last Updated:** `2026-10-02 03:29:36 UTC`

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
| **Execution Vector** | MSHTA / ActiveXObject Stream Dropper | `mshta "javascript:var x=new ActiveXObject('MSXML2.XMLHTTP')..."` | `2026-10-02` | `acmaturaky.cz` |
| **Execution Vector / Dropper** | PowerShell CurrentUser Policy Bypass & Batch Dropper | `powershell -Command "Set-ExecutionPolicy Unrestricted -Scope CurrentUser -Force; Invoke-WebRequest -Uri '.../KL.bat'..."` | `2026-10-02` | `yundatabox.com` |
| **Payload / Persistence** | Trojanized Electron App / GitHub Desktop Backdoor | `resources/app/main.js backdoor (Stages: /r, /g.php)` | `2026-10-02` | `claudedevz.net -> cocuktekstil.com` |
| **Social Engineering Lure** | Fake Secure Gateway (macOS Spotlight / Terminal) | `secure.gateway (Press Cmd+Space to open Spotlight, Type Terminal, Hit Cmd+V)` | `2026-10-02` | `secure.gateway` |

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

### MSHTA / ActiveXObject Stream Dropper (`mshta_activex_dropper`)
* **Category:** Execution Vector
* **Pattern / Signature:** `mshta "javascript:var x=new ActiveXObject('MSXML2.XMLHTTP')..."`
* **First Observed:** 2026-10-02
* **Sample Indicator:** `acmaturaky.cz`
* **Description & Hunting Action:** Victim is instructed to execute an mshta command in the Run box which uses MSXML2.XMLHTTP to fetch remote binaries, ADODB.Stream to write to %TEMP%\verification.exe, and WScript.Shell to execute.

### PowerShell CurrentUser Policy Bypass & Batch Dropper (`batch_executionpolicy_bypass`)
* **Category:** Execution Vector / Dropper
* **Pattern / Signature:** `powershell -Command "Set-ExecutionPolicy Unrestricted -Scope CurrentUser -Force; Invoke-WebRequest -Uri '.../KL.bat'..."`
* **First Observed:** 2026-10-02
* **Sample Indicator:** `yundatabox.com`
* **Description & Hunting Action:** Changes CurrentUser PowerShell execution policy, downloads KL.bat, which creates %TEMP%\myapp, downloads KL.zip, extracts it, and executes KL.exe.

### Trojanized Electron App / GitHub Desktop Backdoor (`trojanized_electron_github_desktop`)
* **Category:** Payload / Persistence
* **Pattern / Signature:** `resources/app/main.js backdoor (Stages: /r, /g.php)`
* **First Observed:** 2026-10-02
* **Sample Indicator:** `claudedevz.net -> cocuktekstil.com`
* **Description & Hunting Action:** ClickFix lure spoofing claude.com (Gateway Verification - Challenge Response ID) delivering a trojanized GitHub Desktop Electron application backdoored via resources/app/main.js communicating with multi-stage C2s.

### Fake Secure Gateway (macOS Spotlight / Terminal) (`macos_spotlight_secure_gateway`)
* **Category:** Social Engineering Lure
* **Pattern / Signature:** `secure.gateway (Press Cmd+Space to open Spotlight, Type Terminal, Hit Cmd+V)`
* **First Observed:** 2026-10-02
* **Sample Indicator:** `secure.gateway`
* **Description & Hunting Action:** Platform-aware ClickFix modal targeting macOS users instructing them to open Spotlight, launch Terminal, and execute obfuscated shell stagers.
