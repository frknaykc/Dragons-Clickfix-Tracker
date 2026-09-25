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
        """Decodes PowerShell UTF-16LE encoded commands and extracts URLs"""
        found_urls = []
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
        return list(set(found_urls))

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
        if "String.fromCharCode" not in dom_or_js or "atob" not in dom_or_js:
            return result

        try:
            arr_m = re.search(r'\[([0-9, ]{100,})\]', dom_or_js)
            k1_var_m = re.search(r'fromCharCode\([^)]*\^\s*([a-zA-Z0-9_$]+)\)', dom_or_js)
            k2_var_m = re.search(r'charCodeAt\([^)]*\)\s*\^\s*([a-zA-Z0-9_$]+)', dom_or_js)

            if not (arr_m and k1_var_m and k2_var_m):
                return result

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
