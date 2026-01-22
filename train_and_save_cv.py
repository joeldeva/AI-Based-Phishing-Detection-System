import pickle
import pandas as pd
import numpy as np

from xgboost import XGBClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import roc_auc_score, accuracy_score, f1_score, precision_score, recall_score

# Base columns available in your CSV
BASE_COLS = [
    "Have_IP", "Have_At", "URL_Length", "URL_Depth",
    "Redirection", "https_Domain", "TinyURL", "Prefix/Suffix"
]

# Derived columns we will add (computed from BASE_COLS)
DERIVED_COLS = [
    "Depth_High", "Suspicious_Sum", "Short_Or_Redirect", "At_Or_IP",
    "Long_And_Deep", "Hyphen_And_Deep"
]

TRAIN_COLS = BASE_COLS + DERIVED_COLS

df = pd.read_csv("DataFiles/5.urldata.csv")

# Labels
if "Label" in df.columns:
    y = df["Label"]
elif "Result" in df.columns:
    y = df["Result"]
else:
    y = df.iloc[:, -1]

# Use only base cols from CSV
X = df[BASE_COLS].apply(pd.to_numeric, errors="coerce").fillna(0)

# Derived features
X["Depth_High"] = (X["URL_Depth"] >= 3).astype(int)

X["Suspicious_Sum"] = (
    X["Have_IP"] + X["Have_At"] + X["URL_Length"] +
    X["Redirection"] + X["TinyURL"] + X["Prefix/Suffix"]
).astype(int)

X["Short_Or_Redirect"] = ((X["TinyURL"] == 1) | (X["Redirection"] == 1)).astype(int)
X["At_Or_IP"] = ((X["Have_At"] == 1) | (X["Have_IP"] == 1)).astype(int)
X["Long_And_Deep"] = ((X["URL_Length"] == 1) & (X["Depth_High"] == 1)).astype(int)
X["Hyphen_And_Deep"] = ((X["Prefix/Suffix"] == 1) & (X["Depth_High"] == 1)).astype(int)

# Ensure order
X = X[TRAIN_COLS]

skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

auc_scores, acc_scores, f1_scores, p_scores, r_scores = [], [], [], [], []
best_models = []

# A small, high-impact parameter set (stable + often improves AUC)
model_params = dict(
    n_estimators=3500,
    max_depth=5,
    learning_rate=0.03,
    subsample=0.9,
    colsample_bytree=0.9,
    min_child_weight=1.0,
    reg_lambda=1.0,
    reg_alpha=0.0,
    gamma=0.0,
    eval_metric="logloss",
    random_state=42,
    n_jobs=-1,
    tree_method="hist"
)

for fold, (tr_idx, va_idx) in enumerate(skf.split(X, y), start=1):
    X_tr, X_va = X.iloc[tr_idx], X.iloc[va_idx]
    y_tr, y_va = y.iloc[tr_idx], y.iloc[va_idx]

    model = XGBClassifier(**model_params)
    model.fit(X_tr, y_tr, eval_set=[(X_va, y_va)], verbose=False)

    proba = model.predict_proba(X_va)[:, 1]
    pred = (proba >= 0.5).astype(int)

    auc = roc_auc_score(y_va, proba)
    acc = accuracy_score(y_va, pred)
    f1  = f1_score(y_va, pred)
    p   = precision_score(y_va, pred, zero_division=0)
    r   = recall_score(y_va, pred, zero_division=0)

    auc_scores.append(auc); acc_scores.append(acc); f1_scores.append(f1)
    p_scores.append(p); r_scores.append(r)

    best_models.append((auc, model))

    print(f"Fold {fold}: AUC={auc:.4f} Acc={acc:.4f} F1={f1:.4f} P={p:.4f} R={r:.4f}")

best_models.sort(key=lambda x: x[0], reverse=True)
best_auc, best_model = best_models[0]

print("\n==== CV Summary (mean) ====")
print("AUC :", round(float(np.mean(auc_scores)), 4))
print("Acc :", round(float(np.mean(acc_scores)), 4))
print("F1  :", round(float(np.mean(f1_scores)), 4))
print("Prec:", round(float(np.mean(p_scores)), 4))
print("Rec :", round(float(np.mean(r_scores)), 4))
print("\nBest fold AUC:", round(best_auc, 4))

# Save model + training columns for runtime alignment
with open("xgb_url_only.pkl", "wb") as f:
    pickle.dump((best_model, TRAIN_COLS), f)

print("\n✅ Saved improved model to xgb_url_only.pkl")
print("Features:", TRAIN_COLS)
