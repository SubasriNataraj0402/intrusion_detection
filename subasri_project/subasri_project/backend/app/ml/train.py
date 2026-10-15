"""
Trains the two detection models used by the platform:

1. RandomForestClassifier  -> supervised classification of known attack types
   (normal / port_scan / ddos / brute_force) from flow features.
2. IsolationForest         -> unsupervised anomaly detector trained only on
   'normal' flows, used to flag traffic that doesn't match any known class
   (zero-day / unknown attack detection).

Run:
  python -m app.ml.train                          # Train using synthetic dataset
  python -m app.ml.train --csv path/to/data.csv   # Train using a CSV dataset

Produces backend/app/ml/models/{scaler,label_encoder,random_forest,isolation_forest}.joblib
"""
import argparse
import os
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder

from app.ml.dataset import generate_dataset, FEATURE_COLUMNS

MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")


def load_dataset(csv_path: str = None, n_per_class: int = 5000) -> pd.DataFrame:
    if csv_path:
        if not os.path.exists(csv_path):
            print(f"Error: Specified CSV file '{csv_path}' does not exist.", file=sys.stderr)
            sys.exit(1)
        print(f"Loading dataset from CSV: {csv_path}")
        df = pd.read_csv(csv_path)
        
        missing_cols = [col for col in FEATURE_COLUMNS + ["label"] if col not in df.columns]
        if missing_cols:
            print(f"Error: CSV missing required column(s): {missing_cols}", file=sys.stderr)
            print(f"Required feature columns: {FEATURE_COLUMNS} + ['label']", file=sys.stderr)
            sys.exit(1)
            
        df = df.dropna(subset=FEATURE_COLUMNS + ["label"])
        print(f"Loaded {len(df)} rows from {csv_path}")
        return df
    else:
        print(f"Generating synthetic dataset ({n_per_class} samples per class)...")
        return generate_dataset(n_per_class=n_per_class)


def main():
    parser = argparse.ArgumentParser(description="Train NIDS ML Models")
    parser.add_argument("--csv", type=str, help="Path to CSV dataset file to train on")
    parser.add_argument("--n-per-class", type=int, default=5000, help="Number of samples per class if generating synthetic data")
    args = parser.parse_args()

    os.makedirs(MODELS_DIR, exist_ok=True)

    df = load_dataset(csv_path=args.csv, n_per_class=args.n_per_class)
    X = df[FEATURE_COLUMNS].values
    y_raw = df["label"].values.astype(str)

    encoder = LabelEncoder()
    y = encoder.fit_transform(y_raw)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    clf = RandomForestClassifier(
        n_estimators=200, max_depth=12, random_state=42, n_jobs=-1, class_weight="balanced"
    )
    clf.fit(X_train_scaled, y_train)

    y_pred = clf.predict(X_test_scaled)
    print("\n=== Random Forest classification report ===")
    print(classification_report(y_test, y_pred, target_names=encoder.classes_))
    print("Confusion matrix:")
    print(confusion_matrix(y_test, y_pred))

    if "normal" in encoder.classes_:
        normal_idx = encoder.transform(["normal"])[0]
        X_normal = X_train_scaled[y_train == normal_idx]
        iso = IsolationForest(n_estimators=200, contamination=0.05, random_state=42, n_jobs=-1)
        iso.fit(X_normal)

        anomaly_pred = iso.predict(X_test_scaled)
        is_attack_true = (y_test != normal_idx).astype(int)
        is_anomaly_pred = (anomaly_pred == -1).astype(int)
        accuracy = np.mean(is_attack_true == is_anomaly_pred)
        print(f"\n=== Isolation Forest anomaly-vs-normal accuracy on held-out set: {accuracy:.3f} ===")
    else:
        print("\nNotice: 'normal' class not present in dataset. Fitting Isolation Forest on full training data.")
        iso = IsolationForest(n_estimators=200, contamination=0.05, random_state=42, n_jobs=-1)
        iso.fit(X_train_scaled)

    joblib.dump(scaler, os.path.join(MODELS_DIR, "scaler.joblib"))
    joblib.dump(encoder, os.path.join(MODELS_DIR, "label_encoder.joblib"))
    joblib.dump(clf, os.path.join(MODELS_DIR, "random_forest.joblib"))
    joblib.dump(iso, os.path.join(MODELS_DIR, "isolation_forest.joblib"))
    print(f"\nSaved models to {MODELS_DIR}")


if __name__ == "__main__":
    main()

