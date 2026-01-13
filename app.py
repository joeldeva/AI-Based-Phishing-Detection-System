"""
🔐 YOURDEFENDER - AI Phishing Detection System
A professional, hackathon-worthy interface with cyberpunk security aesthetic
"""

import streamlit as st
import pickle
import pandas as pd
from urllib.parse import urlparse
import time
import re

# Import your existing feature extraction
from URLFeatureExtraction import featureExtraction, feature_names

# ✅ FIX: Your model file name in folder is xgb_model.pkl
MODEL_PATH = "xgb_model.pkl"

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

def explain_from_features(feat_dict: dict) -> list[dict]:
    reasons = []
    if feat_dict.get("TinyURL") == 1:
        reasons.append({"text": "Uses URL shortener service", "severity": "high", "icon": "🔗"})
    if feat_dict.get("Have_At") == 1:
        reasons.append({"text": "Contains '@' symbol in URL", "severity": "high", "icon": "📧"})
    if feat_dict.get("Prefix/Suffix") == 1:
        reasons.append({"text": "Domain contains hyphen character", "severity": "medium", "icon": "➖"})
    if feat_dict.get("URL_Length") == 1:
        reasons.append({"text": "Unusually long URL detected", "severity": "medium", "icon": "📏"})
    if feat_dict.get("Redirection") == 1:
        reasons.append({"text": "Suspicious '//' redirection pattern", "severity": "high", "icon": "↪️"})
    if feat_dict.get("URL_Depth", 0) >= 3:
        reasons.append({"text": "Deep nested URL path structure", "severity": "low", "icon": "📂"})
    if feat_dict.get("https_Domain") == 1:
        reasons.append({"text": "Domain spoofs 'https' keyword", "severity": "high", "icon": "🔒"})
    # These two are optional (only if you add them as features later)
    if feat_dict.get("Suspicious_TLD") == 1:
        reasons.append({"text": "Suspicious top-level domain", "severity": "medium", "icon": "🌐"})
    if feat_dict.get("IP_Address") == 1:
        reasons.append({"text": "Uses IP address instead of domain", "severity": "high", "icon": "🔢"})
    return reasons[:6]

@st.cache_resource
def load_model():
    with open(MODEL_PATH, "rb") as f:
        return pickle.load(f)

# Page config
st.set_page_config(
    page_title="YOURDEFENDER | AI Phishing Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom CSS for cyberpunk/security aesthetic
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Orbitron:wght@400;500;600;700;800;900&family=Inter:wght@300;400;500;600&display=swap');
    
    :root {
        --primary: #00ff88;
        --primary-dim: #00ff8833;
        --danger: #ff3366;
        --danger-dim: #ff336633;
        --warning: #ffaa00;
        --warning-dim: #ffaa0033;
        --bg-dark: #0a0e17;
        --bg-card: #0f1520;
        --bg-elevated: #151c2c;
        --text-primary: #e8eef7;
        --text-secondary: #6b7a99;
        --border: #1e2940;
        --glow-primary: 0 0 30px #00ff8855, 0 0 60px #00ff8822;
        --glow-danger: 0 0 30px #ff336655, 0 0 60px #ff336622;
    }
    
    .stApp {
        background: var(--bg-dark);
        background-image: 
            radial-gradient(ellipse at 20% 20%, rgba(0, 255, 136, 0.03) 0%, transparent 50%),
            radial-gradient(ellipse at 80% 80%, rgba(255, 51, 102, 0.03) 0%, transparent 50%),
            linear-gradient(180deg, var(--bg-dark) 0%, #0d1219 100%);
    }
    
    #MainMenu, footer, header {visibility: hidden;}
    .stDeployButton {display: none;}

    .hero {
        text-align: center;
        padding: 3rem 0 2rem 0;
        position: relative;
    }
    
    .logo {
        font-family: 'Orbitron', sans-serif;
        font-size: 3.5rem;
        font-weight: 800;
        letter-spacing: 0.3em;
        background: linear-gradient(135deg, var(--primary) 0%, #00ccff 50%, var(--primary) 100%);
        background-size: 200% auto;
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        animation: shine 3s linear infinite;
        margin-bottom: 0.5rem;
        text-shadow: var(--glow-primary);
    }
    
    @keyframes shine {
        to { background-position: 200% center; }
    }
    
    .tagline {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.9rem;
        color: var(--text-secondary);
        letter-spacing: 0.2em;
        text-transform: uppercase;
    }

    .input-section {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 16px;
        padding: 2rem;
        margin: 2rem 0;
        position: relative;
        overflow: hidden;
    }
    
    .input-label {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.75rem;
        color: var(--primary);
        letter-spacing: 0.15em;
        text-transform: uppercase;
        margin-bottom: 0.75rem;
    }

    .stTextInput > div > div > input {
        background: var(--bg-dark) !important;
        border: 1px solid var(--border) !important;
        border-radius: 8px !important;
        color: var(--text-primary) !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 1rem !important;
        padding: 1rem 1.25rem !important;
        transition: all 0.3s ease !important;
    }
    
    .stTextInput > div > div > input:focus {
        border-color: var(--primary) !important;
        box-shadow: 0 0 0 3px var(--primary-dim), var(--glow-primary) !important;
    }

    .stButton > button {
        background: linear-gradient(135deg, var(--primary) 0%, #00ccaa 100%) !important;
        color: var(--bg-dark) !important;
        font-family: 'Orbitron', sans-serif !important;
        font-weight: 600 !important;
        font-size: 0.9rem !important;
        letter-spacing: 0.1em !important;
        padding: 0.875rem 2rem !important;
        border: none !important;
        border-radius: 8px !important;
        cursor: pointer !important;
        transition: all 0.3s ease !important;
        text-transform: uppercase !important;
    }
    
    .stButton > button:hover {
        transform: translateY(-2px) !important;
        box-shadow: var(--glow-primary) !important;
    }

    .result-card {
        background: var(--bg-card);
        border-radius: 16px;
        padding: 2rem;
        margin: 1.5rem 0;
        border: 1px solid var(--border);
        position: relative;
        overflow: hidden;
    }

    .stDataFrame {
        border-radius: 12px !important;
        overflow: hidden !important;
    }
</style>
""", unsafe_allow_html=True)

# Hero Section
st.markdown("""
<div class="hero">
    <div class="logo">YOURDEFENDER</div>
    <div class="tagline">AI-Powered Phishing Detection System</div>
</div>
""", unsafe_allow_html=True)

# Input Section
st.markdown('<div class="input-section">', unsafe_allow_html=True)
st.markdown('<div class="input-label">Enter URL to Analyze</div>', unsafe_allow_html=True)

url = st.text_input(
    label="URL Input",
    placeholder="https://example.com",
    label_visibility="collapsed",
    key="url_input"
)

col1, col2 = st.columns([2, 1])
with col1:
    check = st.button("🔍  ANALYZE URL", use_container_width=True, type="primary")
with col2:
    clear = st.button("CLEAR", use_container_width=True)

st.markdown('</div>', unsafe_allow_html=True)

if clear:
    st.rerun()

if check:
    if not url.strip():
        st.warning("Please enter a URL.")
        st.stop()

    scanning_placeholder = st.empty()
    scanning_placeholder.markdown("""
    <div class="result-card">
        <p style="font-family: 'JetBrains Mono', monospace; color: #00ff88;">
            Scanning URL patterns...
        </p>
    </div>
    """, unsafe_allow_html=True)
    time.sleep(1.0)
    scanning_placeholder.empty()

    if is_trusted(url):
        st.success("✅ VERIFIED TRUSTED DOMAIN (Allowlisted)")
        st.write(f"URL: {url}")
        st.stop()

    model, train_columns = load_model()

    feats = featureExtraction(url.strip())
    feat_dict = dict(zip(feature_names, feats))

    X = pd.DataFrame([[feat_dict.get(c, 0) for c in train_columns]], columns=train_columns)
    X = X.apply(pd.to_numeric, errors="coerce").fillna(0)

    proba = float(model.predict_proba(X)[0][1])

    if proba >= 0.90:
        st.error("🚨 HIGH RISK PHISHING WEBSITE")
    elif proba >= 0.60:
        st.warning("⚠️ SUSPICIOUS WEBSITE (Manual Review Recommended)")
    else:
        st.success("✅ LIKELY LEGITIMATE WEBSITE")

    st.metric("Phishing Risk Score", f"{proba:.4f}")
    st.write(f"URL: {url}")

    # ✅ FIX: Clean feature table (Feature | Value)
    with st.expander("🔬 View Extracted Features", expanded=False):
        feat_df = pd.DataFrame({
            "Feature": list(feat_dict.keys()),
            "Value": list(feat_dict.values())
        })
        st.dataframe(feat_df, use_container_width=True, hide_index=True, height=420)

# Footer
st.markdown("""
<div style="text-align:center; padding: 2rem; color:#6b7a99; font-family:'JetBrains Mono', monospace; font-size:0.75rem;">
YOURDEFENDER • Built with XGBoost ML • Hackathon
</div>
""", unsafe_allow_html=True)
