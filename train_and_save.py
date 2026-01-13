import pickle
import pandas as pd
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, roc_auc_score

URL_ONLY_COLS = [
    "Have_IP", "Have_At", "URL_Length", "URL_Depth",
    "Redirection", "https_Domain", "TinyURL", "Prefix/Suffix"
]

df = pd.read_csv("DataFiles/5.urldata.csv")

# label
if "Label" in df.columns:
    y = df["Label"]
    X = df.drop(columns=["Label"])
elif "Result" in df.columns:
    y = df["Result"]
    X = df.drop(columns=["Result"])
else:
    y = df.iloc[:, -1]
    X = df.iloc[:, :-1]

X = X[URL_ONLY_COLS].apply(pd.to_numeric, errors="coerce").fillna(0)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

model = XGBClassifier(
    n_estimators=500,
    max_depth=4,
    learning_rate=0.07,
    subsample=0.9,
    colsample_bytree=0.9,
    eval_metric="logloss",
    random_state=42
)

model.fit(X_train, y_train)

proba = model.predict_proba(X_test)[:, 1]
pred = (proba >= 0.5).astype(int)

print("Accuracy:", round(accuracy_score(y_test, pred), 4))
print("ROC-AUC :", round(roc_auc_score(y_test, proba), 4))

with open("xgb_url_only.pkl", "wb") as f:
    pickle.dump((model, URL_ONLY_COLS), f)

print("✅ Saved URL-only model to xgb_url_only.pkl")
print("Features:", URL_ONLY_COLS)


