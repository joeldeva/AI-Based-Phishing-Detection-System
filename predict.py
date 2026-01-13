import sys
import pickle
import pandas as pd
from urllib.parse import urlparse

from URLFeatureExtraction import featureExtraction, feature_names

MODEL_PATH = "xgb_url_only.pkl"


TRUSTED_DOMAINS = {
    "google.com",
    "github.com",
    "amazon.com",
    "microsoft.com",
    "microsoftonline.com",
    "office.com",
    "live.com",
    "outlook.com",
    "apple.com",
    "openai.com",
}

def _get_host(url: str) -> str:
    parsed = urlparse(url if "://" in url else "http://" + url)
    return (parsed.hostname or "").lower()

def is_trusted_domain(url: str) -> bool:
    host = _get_host(url)
    return any(host == d or host.endswith("." + d) for d in TRUSTED_DOMAINS)

def explain_from_features(feat_dict: dict) -> list[str]:
    reasons = []

    if feat_dict.get("TinyURL") == 1:
        reasons.append("Uses a URL shortener (often used to hide final destination).")
    if feat_dict.get("Have_At") == 1:
        reasons.append("Contains '@' symbol (can redirect users to a different host).")
    if feat_dict.get("Prefix/Suffix") == 1:
        reasons.append("Domain contains '-' (common in fake look-alike domains).")
    if feat_dict.get("URL_Length") == 1:
        reasons.append("URL is unusually long (often used to confuse users).")
    if feat_dict.get("Redirection") == 1:
        reasons.append("Suspicious '//' redirection found after protocol.")
    if feat_dict.get("URL_Depth", 0) >= 3:
        reasons.append("Deep URL path (multiple folders), often seen in phishing links.")
    if feat_dict.get("https_Domain") == 1:
        reasons.append("Domain contains the word 'https' (misleading pattern).")
    if feat_dict.get("Have_IP") == 1:
        reasons.append("Uses an IP address instead of a domain name.")

    # Page-based features (if your extractor sets these)
    if feat_dict.get("iFrame") == 1:
        reasons.append("Uses iFrame content (sometimes used to hide malicious pages).")
    if feat_dict.get("Mouse_Over") == 1:
        reasons.append("Uses mouse-over scripts (may hide real links).")
    if feat_dict.get("Right_Click") == 1:
        reasons.append("Disables right click/context menu (can block user inspection).")
    if feat_dict.get("Web_Forwards") == 1:
        reasons.append("Multiple redirects detected (can hide final phishing page).")

    return reasons[:6]  # keep it short & clean

def main():
    if len(sys.argv) < 2:
        print('Usage: python predict.py "https://example.com"')
        return

    url = sys.argv[1].strip()

    # Policy layer
    if is_trusted_domain(url):
        print("✅ TRUSTED DOMAIN (Allowlisted)")
        print("Phishing Risk Score: 0.0000")
        print(f"URL: {url}")
        return

    with open(MODEL_PATH, "rb") as f:
        model, train_columns = pickle.load(f)

    feats = featureExtraction(url)
    feat_dict = dict(zip(feature_names, feats))

    X = pd.DataFrame([[feat_dict.get(c, 0) for c in train_columns]], columns=train_columns)
    X = X.apply(pd.to_numeric, errors="coerce").fillna(0)

    proba_class1 = float(model.predict_proba(X)[0][1])

    # Risk-based decision
    if proba_class1 >= 0.90:
        verdict = "🚨 HIGH RISK PHISHING WEBSITE"
    elif proba_class1 >= 0.60:
        verdict = "⚠️ SUSPICIOUS WEBSITE (Manual Review Recommended)"
    else:
        verdict = "✅ LIKELY LEGITIMATE WEBSITE"

    print(verdict)
    print(f"Phishing Risk Score: {proba_class1:.4f}")
    print(f"URL: {url}")

    reasons = explain_from_features(feat_dict)
    if reasons:
        print("\nTop reasons:")
        for r in reasons:
            print(f" - {r}")

if __name__ == "__main__":
    main()
