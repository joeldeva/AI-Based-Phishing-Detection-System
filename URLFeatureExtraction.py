# -*- coding: utf-8 -*-
from urllib.parse import urlparse
import ipaddress
import re

# ============================================================
# Helpers
# ============================================================

def _parsed(url: str):
    """Parse URL safely; ensure scheme exists for urlparse consistency."""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url, urlparse(url)

# ============================================================
# Base URL-only features (8)
# ============================================================

def havingIP(url):
    try:
        url, parsed = _parsed(url)
        host = parsed.hostname or ""
        ipaddress.ip_address(host)
        return 1
    except Exception:
        return 0

def haveAtSign(url):
    return 1 if "@" in url else 0

def getLength(url):
    # dataset style: 1 = suspicious (>=54)
    return 1 if len(url) >= 54 else 0

def getDepth(url):
    url, parsed = _parsed(url)
    path = parsed.path or ""
    parts = [p for p in path.split("/") if p]
    return len(parts)

def redirection(url):
    # suspicious if '//' occurs after protocol
    pos = url.rfind("//")
    if pos <= 6:
        return 0
    return 1 if pos > 7 else 0

def httpDomain(url):
    # In your training set, https_Domain behaves as a URL-starts-with-https signal
    url, _ = _parsed(url)
    return 1 if url.lower().startswith("https://") else 0

shortening_services = (
    r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"
    r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"
    r"short\.to|budurl\.com|ping\.fm|post\.ly|just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|"
    r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|lnkd\.in|db\.tt|"
    r"qr\.ae|adf\.ly|bitly\.com|cur\.lv|tinyurl\.com|ity\.im|q\.gs|po\.st|bc\.vc|"
    r"twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|prettylinkpro\.com|"
    r"scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|link\.zip\.net"
)

def tinyURL(url):
    return 1 if re.search(shortening_services, url, re.IGNORECASE) else 0

def prefixSuffix(url):
    url, parsed = _parsed(url)
    return 1 if "-" in (parsed.hostname or "") else 0

# ============================================================
# Derived interaction features (no raw URL needed beyond base)
# These improve accuracy by capturing combinations.
# ============================================================

def depth_high(url_depth: int) -> int:
    return 1 if url_depth >= 3 else 0

def suspicious_sum(have_ip, have_at, url_len, redir, tiny, hyphen) -> int:
    # Exclude https_Domain because it's not "suspicious" by itself.
    return int(have_ip + have_at + url_len + redir + tiny + hyphen)

def short_or_redirect(tiny, redir) -> int:
    return 1 if (tiny == 1 or redir == 1) else 0

def at_or_ip(have_at, have_ip) -> int:
    return 1 if (have_at == 1 or have_ip == 1) else 0

def long_and_deep(url_len, depth_hi) -> int:
    return 1 if (url_len == 1 and depth_hi == 1) else 0

def hyphen_and_deep(hyphen, depth_hi) -> int:
    return 1 if (hyphen == 1 and depth_hi == 1) else 0

# ============================================================
# Feature Extraction
# ============================================================

def featureExtraction(url):
    # Base
    have_ip = havingIP(url)
    have_at = haveAtSign(url)
    url_len = getLength(url)
    url_depth = getDepth(url)         # numeric
    redir = redirection(url)
    https_dom = httpDomain(url)
    tiny = tinyURL(url)
    hyphen = prefixSuffix(url)

    # Derived
    d_hi = depth_high(url_depth)
    s_sum = suspicious_sum(have_ip, have_at, url_len, redir, tiny, hyphen)
    s_or_r = short_or_redirect(tiny, redir)
    a_or_i = at_or_ip(have_at, have_ip)
    l_and_d = long_and_deep(url_len, d_hi)
    h_and_d = hyphen_and_deep(hyphen, d_hi)

    return [
        have_ip, have_at, url_len, url_depth,
        redir, https_dom, tiny, hyphen,
        d_hi, s_sum, s_or_r, a_or_i, l_and_d, h_and_d
    ]

feature_names = [
    "Have_IP", "Have_At", "URL_Length", "URL_Depth",
    "Redirection", "https_Domain", "TinyURL", "Prefix/Suffix",
    "Depth_High", "Suspicious_Sum", "Short_Or_Redirect", "At_Or_IP",
    "Long_And_Deep", "Hyphen_And_Deep"
]
