"""
avoidance_retrain.py
--------------------
AVOIDANCE LAYER  (Closed-Loop Feedback System)
================================================
Implements the Lambda Architecture "Batch Layer":

  1. Reads ALL detection results from HDFS/local Parquet (written by streaming_detection.py)
  2. Also reads the prevention audit log (logs/prevention_audit.jsonl)
  3. Combines with original training data for a richer, up-to-date dataset
  4. Retrains the Random Forest model
  5. Evaluates the new model vs the old one
  6. Replaces models/model.pkl ONLY if the new model is better
  7. Logs retraining history to logs/retrain_history.jsonl

Run this on a schedule (cron / Task Scheduler) — e.g. every hour or daily.
The updated model.pkl will be picked up by streaming_detection.py on its
next micro-batch (no restart needed if you reload the model inside the UDF).
"""

import os, json, joblib, logging
from datetime import datetime

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import LabelEncoder

# ── CONFIG ────────────────────────────────────────────────────────────
MODEL_PATH          = "models/model.pkl"
NEW_MODEL_TMP       = "models/model_candidate.pkl"
DETECTION_LOGS_DIR  = "logs/detection_results"   # Parquet output from Spark
PREVENTION_AUDIT    = "logs/prevention_audit.jsonl"
ORIGINAL_TRAIN_CSV  = "data/combined_train_80.csv"
RETRAIN_HISTORY     = "logs/retrain_history.jsonl"

MIN_NEW_ROWS        = 100    # only retrain if we have ≥ this many new labelled rows
TARGET_COL          = "label"
DROP_COLS           = ["attack_cat", "prediction", "detection_time",
                       "kafka_ts", "is_attack", "raw_json"]
# ──────────────────────────────────────────────────────────────────────

os.makedirs("models", exist_ok=True)
os.makedirs("logs",   exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [Avoidance] %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("logs/avoidance.log")
    ]
)
log = logging.getLogger(__name__)


# ── HELPERS ───────────────────────────────────────────────────────────

def load_parquet_logs(path: str) -> pd.DataFrame:
    """Load all Parquet part-files written by Spark streaming."""
    if not os.path.exists(path):
        log.warning(f"Parquet log path not found: {path}")
        return pd.DataFrame()
    parts = [
        os.path.join(path, f)
        for f in os.listdir(path)
        if f.endswith(".parquet")
    ]
    if not parts:
        log.warning("No parquet files found in detection log directory.")
        return pd.DataFrame()
    dfs = [pd.read_parquet(p) for p in parts]
    combined = pd.concat(dfs, ignore_index=True)
    log.info(f"Loaded {len(combined)} rows from Parquet detection logs.")
    return combined


def load_original_training(path: str) -> pd.DataFrame:
    if not os.path.exists(path):
        log.warning(f"Original training CSV not found: {path}")
        return pd.DataFrame()
    df = pd.read_csv(path)
    log.info(f"Loaded {len(df)} rows from original training CSV.")
    return df


def prepare_features(df: pd.DataFrame):
    """Drop non-feature columns, encode categoricals, return X, y."""
    df = df.copy()

    # Drop bookkeeping columns
    cols_to_drop = [c for c in DROP_COLS if c in df.columns]
    df.drop(columns=cols_to_drop, inplace=True, errors="ignore")

    if TARGET_COL not in df.columns:
        log.error(f"Target column '{TARGET_COL}' not found.")
        return None, None

    y = df[TARGET_COL]
    X = df.drop(columns=[TARGET_COL])

    # One-hot encode categorical columns
    X = pd.get_dummies(X)

    return X, y


def align_features(X_new: pd.DataFrame, reference_model) -> pd.DataFrame:
    """Align new data columns to what the existing model expects."""
    if hasattr(reference_model, "feature_names_in_"):
        return X_new.reindex(columns=reference_model.feature_names_in_, fill_value=0)
    return X_new


def evaluate_model(model, X_test, y_test) -> float:
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred)
    return acc, report


def write_history(entry: dict):
    with open(RETRAIN_HISTORY, "a") as f:
        f.write(json.dumps(entry) + "\n")

# ── MAIN RETRAINING PIPELINE ──────────────────────────────────────────

def retrain():
    log.info("=" * 60)
    log.info("AVOIDANCE LAYER — Starting model retraining cycle")
    log.info(f"Timestamp: {datetime.utcnow().isoformat()}")
    log.info("=" * 60)

    # 1. Load new labelled data from HDFS detection logs
    new_logs = load_parquet_logs(DETECTION_LOGS_DIR)

    # Keep only rows that actually have a ground-truth label (from dataset)
    if not new_logs.empty and TARGET_COL in new_logs.columns:
        new_logs = new_logs[new_logs[TARGET_COL].notna()]
        log.info(f"New labelled rows from streaming logs: {len(new_logs)}")
    else:
        new_logs = pd.DataFrame()

    if len(new_logs) < MIN_NEW_ROWS:
        log.info(
            f"Only {len(new_logs)} new rows — minimum {MIN_NEW_ROWS} required. "
            "Skipping retraining this cycle."
        )
        write_history({
            "timestamp": datetime.utcnow().isoformat(),
            "status": "SKIPPED",
            "reason": f"Insufficient new data ({len(new_logs)} rows)"
        })
        return

    # 2. Load original training data
    original = load_original_training(ORIGINAL_TRAIN_CSV)

    # 3. Combine
    if not original.empty:
        all_data = pd.concat([original, new_logs], ignore_index=True)
    else:
        all_data = new_logs

    all_data = all_data.sample(frac=1, random_state=42).reset_index(drop=True)
    log.info(f"Combined dataset size for retraining: {len(all_data)} rows")

    # 4. Prepare features
    X, y = prepare_features(all_data)
    if X is None:
        log.error("Feature preparation failed. Aborting.")
        return

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    # 5. Train new candidate model
    log.info("Training new Random Forest candidate...")
    new_model = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        random_state=42,
        n_jobs=-1
    )
    new_model.fit(X_train, y_train)
    new_acc, new_report = evaluate_model(new_model, X_test, y_test)
    log.info(f"Candidate model accuracy: {new_acc:.4f}")
    log.info(f"Classification report:\n{new_report}")

    # 6. Compare against existing model
    old_acc = 0.0
    if os.path.exists(MODEL_PATH):
        old_model = joblib.load(MODEL_PATH)
        X_test_aligned = align_features(X_test, old_model)
        try:
            old_acc, _ = evaluate_model(old_model, X_test_aligned, y_test)
            log.info(f"Existing model accuracy on same test set: {old_acc:.4f}")
        except Exception as e:
            log.warning(f"Could not evaluate old model: {e}. Will replace it.")

    # 7. Replace model if improved (or no model existed)
    if new_acc >= old_acc:
        joblib.dump(new_model, MODEL_PATH)
        log.info(f"✅ Model UPDATED — accuracy improved from {old_acc:.4f} → {new_acc:.4f}")
        status = "UPDATED"
    else:
        log.info(
            f"⚠️  New model ({new_acc:.4f}) did NOT beat existing ({old_acc:.4f}). "
            "Keeping old model."
        )
        joblib.dump(new_model, NEW_MODEL_TMP)  # save as candidate for review
        status = "KEPT_OLD"

    # 8. Write retraining history
    write_history({
        "timestamp":   datetime.utcnow().isoformat(),
        "status":      status,
        "new_accuracy":round(new_acc, 4),
        "old_accuracy":round(old_acc, 4),
        "training_rows": len(X_train),
        "test_rows":     len(X_test),
        "features":      X.shape[1],
    })

    log.info("Retraining cycle complete.\n")


if __name__ == "__main__":
    retrain()
