import os
import joblib


# ============================================================
# MODEL LOCATION
# ============================================================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MODEL_PATH = os.path.join(
    BASE_DIR,
    "ml",
    "models",
    "anti_proxy_model.joblib"
)


# ============================================================
# LOAD MODEL ONCE
# ============================================================

_model = None


def get_model():
    """
    Load the ML model once and reuse it.
    """

    global _model

    if _model is None:

        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                f"Anti-proxy model not found: {MODEL_PATH}"
            )

        _model = joblib.load(MODEL_PATH)

    return _model


# ============================================================
# ML PREDICTION
# ============================================================

def predict_attendance(features):
    """
    Predict whether an attendance attempt is suspicious.

    Required features:

    qr_version
    pin_correct
    typing_time
    scan_to_submit_time
    duplicate_hash
    duplicate_ip
    duplicate_browser
    duplicate_device
    duplicate_session
    gps_accuracy
    distance_from_campus
    """

    required_features = [
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

    # --------------------------------------------------------
    # Validate features
    # --------------------------------------------------------

    missing = [
        feature
        for feature in required_features
        if feature not in features
    ]

    if missing:
        raise ValueError(
            f"Missing ML features: {missing}"
        )

    # --------------------------------------------------------
    # Import pandas only when prediction is requested
    # --------------------------------------------------------

    import pandas as pd

    input_data = pd.DataFrame(
        [[
            features["qr_version"],
            features["pin_correct"],
            features["typing_time"],
            features["scan_to_submit_time"],
            features["duplicate_hash"],
            features["duplicate_ip"],
            features["duplicate_browser"],
            features["duplicate_device"],
            features["duplicate_session"],
            features["gps_accuracy"],
            features["distance_from_campus"],
        ]],
        columns=required_features
    )

    # --------------------------------------------------------
    # Load model
    # --------------------------------------------------------

    model = get_model()

    # --------------------------------------------------------
    # Prediction
    # --------------------------------------------------------

    prediction = int(
        model.predict(input_data)[0]
    )

    probability = float(
        model.predict_proba(input_data)[0][1]
    )

    # --------------------------------------------------------
    # Risk level
    # --------------------------------------------------------

    if probability >= 0.80:

        risk_level = "HIGH"

    elif probability >= 0.50:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"

    return {
        "prediction": prediction,
        "suspicious": prediction == 1,
        "suspicious_probability": round(
            probability,
            4
        ),
        "risk_level": risk_level,
    }