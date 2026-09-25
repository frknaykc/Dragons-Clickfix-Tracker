import requests
import time

class GeoIPEnricher:
    """
    Enriches IP addresses with country, city, ISP, and organization
    using the free ip-api.com service (45 requests/min limit).
    """
    CACHE = {}

    @classmethod
    def enrich_ip(cls, ip: str) -> dict:
        if not ip or ip == "Unknown":
            return {}

        if ip in cls.CACHE:
            return cls.CACHE[ip]

        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,isp,org,as"
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    info = {
                        "country": data.get("country"),
                        "country_code": data.get("countryCode"),
                        "city": data.get("city"),
                        "isp": data.get("isp"),
                        "org": data.get("org"),
                        "as": data.get("as")
                    }
                    cls.CACHE[ip] = info
                    return info
            elif resp.status_code == 429:
                time.sleep(2)
        except Exception:
            pass

        return {}
