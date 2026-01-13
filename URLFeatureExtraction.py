# -*- coding: utf-8 -*-

from urllib.parse import urlparse
import ipaddress
import re
import requests

# ============================================================
# Address bar based features
# ============================================================

def _parsed(url: str):
    """Parse URL safely; ensure scheme exists for urlparse consistency."""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url, urlparse(url)

# 1. Checks for IP address in URL (Have_IP)
def havingIP(url):
    try:
        url, parsed = _parsed(url)
        host = parsed.hostname or ""
        ipaddress.ip_address(host)
        return 1
    except Exception:
        return 0

# 2. Checks presence of '@' symbol (Have_At)
def haveAtSign(url):
    return 1 if "@" in url else 0

# 3. URL length (URL_Length)
def getLength(url):
    # Dataset: 1 = URL length >= 54
    return 1 if len(url) >= 54 else 0


# 4. URL depth (URL_Depth)
def getDepth(url):
    url, parsed = _parsed(url)
    path = parsed.path or ""
    parts = [p for p in path.split("/") if p]
    return len(parts)

# 5. Redirection '//' in URL (Redirection)
def redirection(url):
    pos = url.rfind("//")
    if pos <= 6:
        return 0
    return 1 if pos > 7 else 0

# 6. 'https' token in domain (https_Domain)
def httpDomain(url):
    url, parsed = _parsed(url)
    # 1 = HTTPS is used (SAFE), 0 = HTTP only
    return 1 if url.lower().startswith("https://") else 0


# Shortening services
shortening_services = (
    r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"
    r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"
    r"short\.to|budurl\.com|ping\.fm|post\.ly|just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|"
    r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|lnkd\.in|db\.tt|"
    r"qr\.ae|adf\.ly|bitly\.com|cur\.lv|tinyurl\.com|ity\.im|q\.gs|po\.st|bc\.vc|"
    r"twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|prettylinkpro\.com|"
    r"scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|link\.zip\.net"
)

# 7. URL shortening service (TinyURL)
def tinyURL(url):
    return 1 if re.search(shortening_services, url, re.IGNORECASE) else 0

# 8. '-' in domain (Prefix/Suffix)
def prefixSuffix(url):
    url, parsed = _parsed(url)
    return 1 if "-" in (parsed.hostname or "") else 0


# ============================================================
# NEW FEATURE (important)
# ============================================================

# 9. Subdomain count
def subdomain_count(url):
    url, parsed = _parsed(url)
    host = parsed.hostname or ""
    # example: a.b.c.com -> 2 subdomains
    return max(0, host.count('.') - 1)


# ============================================================
# Domain based features (OFFLINE-SAFE)
# ============================================================

import socket  # add at the top with imports

def dns_record_offline(url):
    """
    1 = DNS record exists (legit signal)
    0 = no DNS / cannot resolve (phishy signal)
    """
    try:
        url, parsed = _parsed(url)
        host = parsed.hostname or ""
        if not host:
            return 0
        socket.gethostbyname(host)
        return 1
    except Exception:
        return 0


def web_traffic_offline(_url):
    # dataset: 1 = popular / legit
    return 1



def domain_age_offline(_url):
    # dataset: 1 = old domain (assume legit if unknown)
    return 1

def domain_end_offline(_url):
    # dataset: 1 = long expiry (assume legit if unknown)
    return 1



# ============================================================
# HTML & JavaScript based features
# ============================================================

def _safe_get(url: str):
    try:
        url, parsed = _parsed(url)
        return requests.get(
            url,
            timeout=5,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"}
        )
    except Exception:
        return None

# 15. IFrame Redirection
def iframe(response):
    if response is None:
        return 0
    return 1 if re.search(r"<\s*iframe\b|frameborder\s*=", response.text, re.IGNORECASE) else 0

# 16. Status Bar Customization
def mouseOver(response):
    if response is None:
        return 0
    return 1 if re.search(r"onmouseover\s*=", response.text, re.IGNORECASE) else 0

# 17. Disabling Right Click
def rightClick(response):
    if response is None:
        return 1   # normal behavior
    return 0 if re.search(r"event\.button\s*==\s*2|contextmenu", response.text, re.IGNORECASE) else 1


# 18. Website Forwarding
def forwarding(response):
    if response is None:
        return 0
    return 1 if len(getattr(response, "history", [])) > 2 else 0


# ============================================================
# Feature Extraction
# ============================================================

def featureExtraction(url):
    features = []

    features.append(havingIP(url))
    features.append(haveAtSign(url))
    features.append(getLength(url))
    features.append(getDepth(url))
    features.append(redirection(url))
    features.append(httpDomain(url))
    features.append(tinyURL(url))
    features.append(prefixSuffix(url))

    features.append(dns_record_offline(url))
    features.append(web_traffic_offline(url))
    features.append(domain_age_offline(url))
    features.append(domain_end_offline(url))

    response = _safe_get(url)
    features.append(iframe(response))
    features.append(mouseOver(response))
    features.append(rightClick(response))
    features.append(forwarding(response))

    return features



feature_names = [
    'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection',
    'https_Domain', 'TinyURL', 'Prefix/Suffix',
    'DNS_Record', 'Web_Traffic', 'Domain_Age', 'Domain_End',
    'iFrame', 'Mouse_Over', 'Right_Click', 'Web_Forwards'
]

