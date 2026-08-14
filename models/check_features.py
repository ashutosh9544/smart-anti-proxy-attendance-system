import os
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.metrics import classification_report, roc_auc_score

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "ml_training_data.csv")

df = pd.read_csv(DATA_PATH)

TARGET = "teacher_label"

# Same identifiers/rule outputs excluded from ML
DROP_COLUMNS = [
    "attendance_id",
    "student_id",
    "session_id",
    "fingerprint_hash",
    "risk_score",
    "rule_label",
    "created_at",
]

X = df.drop(columns=[TARGET] + DROP_COLUMNS)
y = df[TARGET]

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

model = RandomForestClassifier(
    n_estimators=300,
    random_state=42,
    class_weight="balanced",
    n_jobs=-1
)

model.fit(X_train, y_train)

predictions = model.predict(X_test)
probabilities = model.predict_proba(X_test)[:, 1]

print("=" * 60)
print("FEATURE IMPORTANCE / LEAKAGE CHECK")
print("=" * 60)

print("\nROC-AUC:", round(roc_auc_score(y_test, probabilities), 4))

print("\nClassification report:")
print(classification_report(
    y_test,
    predictions,
    target_names=["Legitimate", "Suspicious"],
    zero_division=0
))

# ------------------------------------------------------------
# FEATURE IMPORTANCE
# ------------------------------------------------------------

importance = pd.DataFrame({
    "feature": X.columns,
    "importance": model.feature_importances_
}).sort_values(
    "importance",
    ascending=False
)

print("\nFeature importance:")
print(importance.to_string(index=False))

# ------------------------------------------------------------
# PERMUTATION IMPORTANCE
# ------------------------------------------------------------

perm = permutation_importance(
    model,
    X_test,
    y_test,
    n_repeats=10,
    random_state=42,
    scoring="f1",
    n_jobs=-1
)

permutation_df = pd.DataFrame({
    "feature": X.columns,
    "importance": perm.importances_mean
}).sort_values(
    "importance",
    ascending=False
)

print("\nPermutation importance:")
print(permutation_df.to_string(index=False))

# ------------------------------------------------------------
# SAVE RESULTS
# ------------------------------------------------------------

importance.to_csv(
    os.path.join(BASE_DIR, "models", "feature_importance.csv"),
    index=False
)

permutation_df.to_csv(
    os.path.join(BASE_DIR, "models", "permutation_importance.csv"),
    index=False
)

# ------------------------------------------------------------
# GRAPH
# ------------------------------------------------------------

plt.figure(figsize=(10, 6))

plt.barh(
    importance["feature"],
    importance["importance"]
)

plt.xlabel("Importance")
plt.ylabel("Feature")
plt.title("Anti-Proxy ML Feature Importance")

plt.gca().invert_yaxis()

plt.tight_layout()

graph_path = os.path.join(
    BASE_DIR,
    "models",
    "feature_importance.png"
)

plt.savefig(graph_path, dpi=150)

print("\nSaved:")
print(" - models/feature_importance.csv")
print(" - models/permutation_importance.csv")
print(" - models/feature_importance.png")