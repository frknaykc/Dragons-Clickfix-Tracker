import re

def defang_url(url: str) -> str:
    """
    Converts https://malware.com/path -> hxxps://malware[.]com/path
    Protects against accidental clicks and GitHub abuse filters.
    """
    if not url:
        return ""
    # Replace http/https
    url = re.sub(r'^https://', 'hxxps://', url, flags=re.IGNORECASE)
    url = re.sub(r'^http://', 'hxxp://', url, flags=re.IGNORECASE)
    # Defang dots in the domain part only
    parts = url.split('/', 3)
    if len(parts) >= 3:
        parts[2] = parts[2].replace('.', '[.]')
        return '/'.join(parts)
    return url.replace('.', '[.]')

def defang_domain(domain: str) -> str:
    """
    Converts malware.com -> malware[.]com
    """
    if not domain:
        return ""
    return domain.replace('.', '[.]')

def defang_ip(ip: str) -> str:
    """
    Converts 1.2.3.4 -> 1.2.3[.]4
    """
    if not ip:
        return ""
    parts = ip.split('.')
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}[.]{parts[3]}"
    return ip.replace('.', '[.]')
