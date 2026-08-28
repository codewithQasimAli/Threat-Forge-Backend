"""
Kitsune Model Health Diagnostic
================================
Inspects the trained kitsune_latest.pkl and runs sample CICIDS2017 flows
through it to determine if the model itself is healthy or if it was
under-trained / broken during FYP1.

Output interprets three scenarios:
  A) Model is fine — distribution shift is the real issue, retraining on
     GNS3 benign is likely to help.
  B) Model cannot discriminate even on its own training-distribution data
     — retraining won't save us, use rule-based post-filter instead.
  C) Model produces degenerate output (all zeros, all NaN) — broken model,
     needs retraining from scratch or fallback.
"""

import pickle
import sys
from pathlib import Path

import numpy as np

# ---------------------------------------------------------------------------
# sys.path setup so Kitsune modules import cleanly
# ---------------------------------------------------------------------------
current_dir = Path(__file__).parent
app_dir = current_dir.parent
root_dir = app_dir.parent
kitsune_path = root_dir / "services" / "Kitsune-py"
if kitsune_path.exists():
    sys.path.insert(0, str(kitsune_path))
sys.path.insert(0, str(root_dir))

MODEL_PATH = root_dir / "models" / "kitsune_latest.pkl"


def section(title):
    print("\n" + "=" * 70)
    print(f" {title}")
    print("=" * 70)


def main():
    section("KITSUNE MODEL HEALTH DIAGNOSTIC")

    # ------------------------------------------------------------------
    # Load the pkl and inspect its contents
    # ------------------------------------------------------------------
    if not MODEL_PATH.exists():
        print(f"ERROR: Model not found at {MODEL_PATH}")
        return

    print(f"Loading: {MODEL_PATH}")
    with open(MODEL_PATH, "rb") as f:
        model_data = pickle.load(f)

    section("STEP 1 — PKL CONTENTS INVENTORY")
    print(f"Keys in pkl: {list(model_data.keys())}")

    if "kitsune" not in model_data:
        print("ERROR: No 'kitsune' key in pkl. Model is fundamentally broken.")
        return

    kitsune    = model_data["kitsune"]
    norm       = model_data.get("norm_params", None)
    features   = model_data.get("feature_columns", [])
    threshold  = model_data.get("threshold", None)

    print(f"Trained threshold: {threshold}")
    print(f"Feature count in pkl: {len(features)}")
    if norm is not None:
        try:
            print(f"Norm params shape: min={norm['min'].shape}, range={norm['range'].shape}")
        except Exception as e:
            print(f"Norm params inspection failed: {e}")

    # ------------------------------------------------------------------
    # Locate CICIDS2017 preprocessed CSVs
    # ------------------------------------------------------------------
    section("STEP 2 — LOCATE CICIDS2017 SAMPLE FILES")

    monday_benign = root_dir / "datasets" / "CICIDS2017" / "preprocessed" / "Monday-WorkingHours.pcap_ISCX_preprocessed.csv"
    friday_ddos   = root_dir / "datasets" / "CICIDS2017" / "preprocessed" / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX_preprocessed.csv"

    print(f"Monday benign: {monday_benign.exists()} — {monday_benign}")
    print(f"Friday DDoS:   {friday_ddos.exists()} — {friday_ddos}")

    if not monday_benign.exists() or not friday_ddos.exists():
        print("\nWARNING: One or both CICIDS2017 CSVs missing. Limited diagnostic possible.")
        print("Falling back to NaN/zero check only.")
        test_model_determinism(kitsune, norm, features)
        return

    # ------------------------------------------------------------------
    # Run sample benign and sample attack flows through the model
    # ------------------------------------------------------------------
    import pandas as pd

    def load_sample(csv_path, n=500, label_filter=None):
        """Load up to n rows from a CICIDS2017 preprocessed CSV."""
        try:
            df = pd.read_csv(csv_path, encoding="latin-1", low_memory=False, nrows=50000)
        except Exception as e:
            print(f"  Failed to read {csv_path.name}: {e}")
            return None, None
        df.columns = df.columns.str.strip()
        if label_filter and "Label" in df.columns:
            df = df[df["Label"].str.strip() == label_filter]
        if len(df) == 0:
            return None, None
        df = df.head(n)
        # Extract the feature columns used at training time
        missing = [c for c in features if c not in df.columns]
        if missing:
            print(f"  WARNING: {len(missing)} expected features missing from {csv_path.name}")
            return None, None
        X = df[features].to_numpy(dtype=np.float64)
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        return X, df

    def normalize(X):
        if norm is None:
            return np.clip(X, 0.0, 1.0)
        try:
            mn = norm["min"]
            rg = norm["range"]
            if mn.shape[0] != X.shape[1]:
                return np.clip(X, 0.0, 1.0)
            return np.clip((X - mn) / (rg + 1e-10), 0.0, 1.0)
        except Exception:
            return np.clip(X, 0.0, 1.0)

    def run_rmse(X, label):
        rmses = []
        for i in range(X.shape[0]):
            r = kitsune.process(X[i])
            if r is not None:
                rmses.append(float(r))
        arr = np.array(rmses)
        nz = arr[arr > 0]
        print(f"\n  {label}:")
        print(f"    Total samples processed: {len(rmses)}")
        print(f"    Non-zero RMSE samples:   {len(nz)}")
        if len(nz) > 0:
            print(f"    Mean RMSE:   {nz.mean():.6f}")
            print(f"    Median RMSE: {np.median(nz):.6f}")
            print(f"    Std RMSE:    {nz.std():.6f}")
            print(f"    Min RMSE:    {nz.min():.6f}")
            print(f"    Max RMSE:    {nz.max():.6f}")
        else:
            print(f"    All RMSE were zero — model is either in grace period or broken")
        return nz

    section("STEP 3 — SAMPLE CICIDS2017 BENIGN THROUGH MODEL")
    Xb, _ = load_sample(monday_benign, n=500, label_filter="BENIGN")
    if Xb is None or Xb.shape[0] == 0:
        print("  Could not load Monday benign samples — skipping benign test")
        benign_nz = np.array([])
    else:
        print(f"  Loaded {Xb.shape[0]} benign samples, feature dim {Xb.shape[1]}")
        Xbn = normalize(Xb)
        benign_nz = run_rmse(Xbn, "BENIGN (CICIDS2017 Monday)")

    section("STEP 4 — SAMPLE CICIDS2017 DDoS THROUGH MODEL")
    Xa, _ = load_sample(friday_ddos, n=500, label_filter="DDoS")
    if Xa is None or Xa.shape[0] == 0:
        # Try without label filter — some preprocessed versions don't have DDoS label
        Xa, _ = load_sample(friday_ddos, n=500, label_filter=None)
    if Xa is None or Xa.shape[0] == 0:
        print("  Could not load Friday DDoS samples — skipping attack test")
        attack_nz = np.array([])
    else:
        print(f"  Loaded {Xa.shape[0]} attack samples, feature dim {Xa.shape[1]}")
        Xan = normalize(Xa)
        attack_nz = run_rmse(Xan, "DDoS (CICIDS2017 Friday)")

    # ------------------------------------------------------------------
    # Interpret results
    # ------------------------------------------------------------------
    section("STEP 5 — INTERPRETATION")

    if len(benign_nz) == 0 and len(attack_nz) == 0:
        print("Could not get RMSE data. Model may be entirely broken or CSVs unavailable.")
        return

    if len(benign_nz) > 0 and len(attack_nz) > 0:
        b_mean = benign_nz.mean()
        a_mean = attack_nz.mean()
        ratio = a_mean / b_mean if b_mean > 0 else float("inf")
        separation = a_mean - b_mean

        print(f"\n  Benign mean RMSE: {b_mean:.6f}")
        print(f"  Attack mean RMSE: {a_mean:.6f}")
        print(f"  Attack/Benign ratio: {ratio:.2f}x")
        print(f"  Absolute separation: {separation:.6f}")

        print("\n  DIAGNOSIS:")
        if ratio > 5.0 and separation > 0.001:
            print("  SCENARIO A — Model is healthy. Attack RMSE clearly above benign.")
            print("  -> Distribution shift on GNS3 data is the real issue.")
            print("  -> Retraining on GNS3 benign has HIGH probability of working.")
        elif ratio > 1.5:
            print("  SCENARIO A-weak — Model discriminates but weakly.")
            print("  -> Retraining on GNS3 benign MAY help but outcome uncertain.")
            print("  -> Consider rule-based post-filter as parallel approach.")
        elif ratio < 1.2 and ratio > 0.8:
            print("  SCENARIO B — Model cannot meaningfully discriminate.")
            print("  -> Original training was insufficient or features mismatched.")
            print("  -> DO NOT waste time retraining — go straight to rule-based post-filter.")
        else:
            print("  SCENARIO C — Unexpected pattern. Investigate further.")
            print(f"  -> Ratio {ratio:.2f}x, separation {separation:.6f}")
    elif len(benign_nz) == 0:
        print("  No benign RMSE data. Cannot assess discrimination.")
    elif len(attack_nz) == 0:
        print("  No attack RMSE data. Cannot assess discrimination.")

    section("STEP 6 — RECOMMENDED NEXT ACTION")
    print("Review the mean/median RMSE values and the Scenario label above")
    print("to determine the appropriate calibration path forward.")


def test_model_determinism(kitsune, norm, features):
    """When CICIDS CSVs unavailable, at least verify model doesn't output NaN/garbage."""
    section("FALLBACK — MODEL DETERMINISM CHECK")
    fake = np.zeros(52, dtype=np.float64)
    try:
        r = kitsune.process(fake)
        print(f"  Zero-vector RMSE: {r}")
    except Exception as e:
        print(f"  ERROR processing zero vector: {e}")

    rng = np.random.default_rng(42)
    rand = rng.random(52)
    try:
        r = kitsune.process(rand)
        print(f"  Random-vector RMSE: {r}")
    except Exception as e:
        print(f"  ERROR processing random vector: {e}")


if __name__ == "__main__":
    main()
