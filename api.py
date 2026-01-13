import pickle
import pandas as pd
from fastapi import FastAPI
from pydantic import BaseModel
from urllib.parse import urlparse

from URLFeatureExtraction import featureExtraction, feature_names

MODEL_PATH = "xgb_model.pkl"

  # use url-only model

TRUSTED_DOMAINS = {
    "google.com", "github.com", "amazon.com",
    "microsoft.com", "microsoftonline.com", "office.com", "live.com", "outlook.com",
    "apple.com", "openai.com"
}

def _host(url: str) -> str:
    p = urlparse(url if "://" in url else "http://" + url)
    return (p.hostname or "").lower()

def is_trusted(url: str) -> bool:
    h = _host(url)
    return any(h == d or h.endswith("." + d) for d in TRUSTED_DOMAINS)

def explain_from_features(feat_dict: dict) -> list[str]:
    reasons = []
    if feat_dict.get("TinyURL") == 1: reasons.append("Uses a URL shortener.")
    if feat_dict.get("Have_At") == 1: reasons.append("Contains '@' symbol.")
    if feat_dict.get("Prefix/Suffix") == 1: reasons.append("Domain contains '-'.")
    if feat_dict.get("URL_Length") == 1: reasons.append("URL is unusually long.")
    if feat_dict.get("Redirection") == 1: reasons.append("Suspicious '//' redirection.")
    if feat_dict.get("URL_Depth", 0) >= 3: reasons.append("Deep URL path.")
    return reasons[:6]

with open(MODEL_PATH, "rb") as f:
    model, train_columns = pickle.load(f)

app = FastAPI(title="Phishing Detection API")

class UrlIn(BaseModel):
    url: str

@app.post("/predict")
def predict(payload: UrlIn):
    url = payload.url.strip()

    if is_trusted(url):
        return {
            "url": url,
            "verdict": "TRUSTED_DOMAIN",
            "risk_score": 0.0,
            "reasons": ["Domain is allowlisted."],
            "features": {}
        }

    feats = featureExtraction(url)
    feat_dict = dict(zip(feature_names, feats))

    X = pd.DataFrame([[feat_dict.get(c, 0) for c in train_columns]], columns=train_columns)
    X = X.apply(pd.to_numeric, errors="coerce").fillna(0)

    proba = float(model.predict_proba(X)[0][1])

    if proba >= 0.90:
        verdict = "HIGH_RISK_PHISHING"
    elif proba >= 0.60:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LIKELY_LEGIT"

    return {
        "url": url,
        "verdict": verdict,
        "risk_score": proba,
        "reasons": explain_from_features(feat_dict),
        "features": {k: feat_dict.get(k, 0) for k in train_columns}
    }
