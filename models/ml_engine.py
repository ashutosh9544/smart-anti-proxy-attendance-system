import os
import joblib
import numpy as np

from sklearn.linear_model import SGDClassifier


MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "models",
    "anti_proxy_model.joblib"
)


FEATURE_NAMES = [
    "duplicate_hash",
    "duplicate_ip",
    "duplicate_browser",
    "duplicate_device",
    "duplicate_session",
    "scan_to_submit_time",
    "typing_time",
    "qr_version",
    "gps_accuracy",
    "distance_from_campus",
    "inside_geofence"
]


def create_model():
    return SGDClassifier(
        loss="log_loss",
        random_state=42
    )


def load_model():

    if os.path.exists(MODEL_PATH):
        return joblib.load(MODEL_PATH)

    return None


def save_model(model):

    os.makedirs(
        os.path.dirname(MODEL_PATH),
        exist_ok=True
    )

    joblib.dump(model, MODEL_PATH)


def train_initial_model(X, y):

    model = create_model()

    model.partial_fit(
        np.asarray(X),
        np.asarray(y),
        classes=np.array([0, 1])
    )

    save_model(model)

    return model


def predict(features):

    model = load_model()

    if model is None:
        return None

    X = np.array([
        [features.get(name, 0) for name in FEATURE_NAMES]
    ])

    probability = model.predict_proba(X)[0][1]

    return float(probability)


def update_model(X, y):

    model = load_model()

    if model is None:
        return train_initial_model(X, y)

    model.partial_fit(
        np.asarray(X),
        np.asarray(y)
    )

    save_model(model)

    return model