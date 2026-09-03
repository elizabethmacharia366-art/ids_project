import argparse
import logging

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from detection.ml_engine import FEATURE_NAMES

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("ids.train")


def main():
    parser = argparse.ArgumentParser(description="Train the IDS anomaly model")
    parser.add_argument("--csv", required=True, help="CSV of normal-traffic flow features")
    parser.add_argument("--model-out", default="models/anomaly_model.joblib")
    parser.add_argument("--scaler-out", default="models/scaler.joblib")
    parser.add_argument("--contamination", type=float, default=0.02,
                         help="Expected proportion of outliers even in 'normal' data")
    parser.add_argument("--n-estimators", type=int, default=200)
    args = parser.parse_args()

    df = pd.read_csv(args.csv)
    missing = [c for c in FEATURE_NAMES if c not in df.columns]
    if missing:
        raise SystemExit(f"CSV is missing required columns: {missing}")

    X = df[FEATURE_NAMES].values
    log.info("Training on %d flows, %d features", X.shape[0], X.shape[1])

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=args.n_estimators,
        contamination=args.contamination,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_scaled)

    joblib.dump(model, args.model_out)
    joblib.dump(scaler, args.scaler_out)
    log.info("Saved model -> %s", args.model_out)
    log.info("Saved scaler -> %s", args.scaler_out)

    scores = model.decision_function(X_scaled)
    log.info(
        "Training-set score stats: min=%.3f max=%.3f mean=%.3f — use these to sanity-check "
        "ml_score_threshold in config.yaml",
        scores.min(), scores.max(), scores.mean(),
    )


if __name__ == "__main__":
    main()
