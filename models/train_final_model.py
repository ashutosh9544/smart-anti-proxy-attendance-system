import os
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
    confusion_matrix,
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_PATH = os.path.join(
    BASE_DIR,
    "ml_training_data.csv"
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "ml",
    "models"
)

os.makedirs(MODEL_DIR, exist_ok=True)


# ============================================================
# LOAD DATA
# ============================================================

print("=" * 60)
print("FINAL ANTI-PROXY ML MODEL")
print("=" * 60)

df = pd.read_csv(DATA_PATH)

print("\nDataset:", df.shape)


# ============================================================
# FEATURES
# ============================================================

FEATURES = [
    "qr_version",
    "pin_correct",
    "typing_time",
    "scan_to_submit_time",
    "duplicate_hash",
    "duplicate_ip",
    "duplicate_browser",
    "duplicate_device",
    "duplicate_session",
    "gps_accuracy",
    "distance_from_campus",
]

TARGET = "teacher_label"

X = df[FEATURES]
y = df[TARGET]


print("\nFinal ML features:")

for feature in FEATURES:
    print(" -", feature)


# ============================================================
# TRAIN / TEST SPLIT
# ============================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTraining samples:", len(X_train))
print("Testing samples :", len(X_test))


# ============================================================
# MODEL
# ============================================================

model = Pipeline(
    steps=[
        (
            "imputer",
            SimpleImputer(strategy="median")
        ),

        (
            "scaler",
            StandardScaler()
        ),

        (
            "classifier",
            LogisticRegression(
                max_iter=2000,
                class_weight="balanced",
                random_state=42
            )
        )
    ]
)


# ============================================================
# TRAIN
# ============================================================

print("\nTraining model...")

model.fit(
    X_train,
    y_train
)


# ============================================================
# PREDICTION
# ============================================================

predictions = model.predict(X_test)

probabilities = model.predict_proba(
    X_test
)[:, 1]


# ============================================================
# EVALUATION
# ============================================================

accuracy = accuracy_score(
    y_test,
    predictions
)

precision = precision_score(
    y_test,
    predictions,
    zero_division=0
)

recall = recall_score(
    y_test,
    predictions,
    zero_division=0
)

f1 = f1_score(
    y_test,
    predictions,
    zero_division=0
)

roc_auc = roc_auc_score(
    y_test,
    probabilities
)


print("\n" + "=" * 60)
print("FINAL MODEL RESULTS")
print("=" * 60)

print(
    f"\nAccuracy : {accuracy:.4f}"
)

print(
    f"Precision: {precision:.4f}"
)

print(
    f"Recall   : {recall:.4f}"
)

print(
    f"F1 Score : {f1:.4f}"
)

print(
    f"ROC-AUC  : {roc_auc:.4f}"
)


print("\nClassification Report:")

print(
    classification_report(
        y_test,
        predictions,
        target_names=[
            "Legitimate",
            "Suspicious"
        ],
        zero_division=0
    )
)


print("Confusion Matrix:")

print(
    confusion_matrix(
        y_test,
        predictions
    )
)


# ============================================================
# SAVE MODEL
# ============================================================

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "anti_proxy_model.joblib"
)

joblib.dump(
    model,
    MODEL_PATH
)

print("\nModel saved to:")

print(MODEL_PATH)


# ============================================================
# SAVE FEATURE LIST
# ============================================================

FEATURE_PATH = os.path.join(
    MODEL_DIR,
    "model_features.txt"
)

with open(
    FEATURE_PATH,
    "w",
    encoding="utf-8"
) as file:

    for feature in FEATURES:
        file.write(feature + "\n")


print("\nFeature list saved to:")

print(FEATURE_PATH)

print("\nTraining completed successfully.")