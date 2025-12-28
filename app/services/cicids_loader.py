"""
CICIDS2017 Dataset Loader for Kitsune (Professional + Dynamic Alerts)
====================================================================

What this script does
---------------------
1) Train KitNET (Kitsune) on Monday BENIGN traffic (normal behavior learning)
2) Detect anomalies on Friday DDoS / PortScan files
3) Evaluate metrics using CICIDS labels (BENIGN vs ATTACK)
4) Optionally create alerts dynamically in your backend DB by calling:
      POST {api_url}/alerts/alerts

Key fixes / guarantees
----------------------
- Uses the SAME feature columns for train + detect (saved in model)
- Uses the SAME normalization parameters from training during detection
- Avoids "double normalization" bugs
- Gives detailed statistics and metrics (no emojis)
- Optional threshold calibration on BENIGN samples inside the detect file
- Dynamic alert emission with throttling (avoid flooding DB)

Usage examples
--------------
Train (Monday BENIGN):
  python app/services/cicids_loader.py --mode train \
    --file datasets/CICIDS2017/preprocessed/Monday-WorkingHours.pcap_ISCX_preprocessed.csv \
    --max-rows 50000

Detect (Friday DDoS) using saved threshold:
  python app/services/cicids_loader.py --mode detect \
    --file datasets/CICIDS2017/preprocessed/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX_preprocessed.csv

Detect with BENIGN calibration (recommended if performance is bad):
  python app/services/cicids_loader.py --mode detect \
    --file datasets/CICIDS2017/preprocessed/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX_preprocessed.csv \
    --calibrate-benign 20000

Detect + create alerts dynamically via your API:
  python app/services/cicids_loader.py --mode detect \
    --file datasets/CICIDS2017/preprocessed/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX_preprocessed.csv \
    --emit-alerts --api-url http://localhost:8000 --user-id 1 --device-id 1 \
    --max-alerts 2000 --alert-gap-rows 200 --alert-cooldown 0.25

Notes
-----
- For best Kitsune behavior, train on a large Monday subset (e.g., 200k+ rows if possible).
- If Friday has many BENIGN rows but you flag them as anomalies, calibrate threshold on BENIGN.
"""

import argparse
import json
import pickle
import sys
import time
import warnings
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
import requests

warnings.filterwarnings("ignore")


# -------------------------------------------------------------------
# KitNET import setup (matches your project structure)
# -------------------------------------------------------------------
current_dir = Path(__file__).parent          # app/services/
app_dir = current_dir.parent                 # app/
root_dir = app_dir.parent                    # backend/Threat-Forge-Backend/
kitsune_path = root_dir / "services" / "Kitsune-py"

if kitsune_path.exists():
    sys.path.insert(0, str(kitsune_path))
    print(f"Added to path: {kitsune_path}")
else:
    print(f"KitNET path not found: {kitsune_path}")
    print(f"Current file: {__file__}")
    print("Please ensure KitNET is installed at services/Kitsune-py")
    raise SystemExit(1)

try:
    from KitNET.KitNET import KitNET
    print("KitNET imported successfully")
except ImportError as e:
    print(f"Error importing KitNET: {e}")
    raise SystemExit(1)

# ===========================================================================
# Interactive Mode Functions
# ===========================================================================

def print_header():
    """Print interactive mode header"""
    print("=" * 70)
    print("KITSUNE IDS - INTERACTIVE MODE")
    print("=" * 70)
    print()


def get_mode() -> str:
    """Prompt for train or detect mode"""
    print("SELECT MODE:")
    print("   1. Train (learn normal behavior)")
    print("   2. Detect (find anomalies)")
    print()
    
    while True:
        choice = input("Enter choice (1 or 2): ").strip()
        if choice == "1":
            return "train"
        elif choice == "2":
            return "detect"
        else:
            print("Invalid choice. Please enter 1 or 2.")


def get_file_path(mode: str) -> str:
    """Prompt for file path with file browser"""
    print(f"\nSELECT {mode.upper()} FILE:")
    
    base_path = Path("datasets/CICIDS2017/preprocessed")
    if base_path.exists():
        files = list(base_path.glob("*.csv"))
        if files:
            print("\n   Available files:")
            for i, file in enumerate(files, 1):
                size_mb = file.stat().st_size / (1024 * 1024)
                print(f"   {i}. {file.name} ({size_mb:.1f} MB)")
            print()
            
            choice = input(f"Enter file number (or press Enter for custom path): ").strip()
            if choice.isdigit() and 1 <= int(choice) <= len(files):
                return str(files[int(choice) - 1])
    
    custom_path = input("Enter full file path: ").strip()
    return custom_path


def get_max_rows() -> Optional[int]:
    """Prompt for maximum rows to process"""
    print("\nMAXIMUM ROWS:")
    print("   Enter max rows to process (or press Enter for ALL)")
    
    choice = input("Max rows: ").strip()
    if not choice:
        return None
    
    try:
        return int(choice)
    except ValueError:
        print("Invalid number, using ALL rows")
        return None


def get_threshold() -> Optional[float]:
    """Prompt for detection threshold"""
    print("\nDETECTION THRESHOLD:")
    print("   Recommended: 0.020 for DDoS, 0.025-0.030 for other attacks")
    print("   Press Enter to use saved/auto threshold")
    
    choice = input("Threshold: ").strip()
    if not choice:
        return None
    
    try:
        return float(choice)
    except ValueError:
        print("Invalid number, using auto threshold")
        return None


def get_alert_settings() -> Dict:
    """Prompt for alert generation settings"""
    print("\nALERT GENERATION:")
    choice = input("Generate alerts in database? (y/n): ").strip().lower()
    
    if choice != 'y':
        return {'emit_alerts': False}
    
    settings = {'emit_alerts': True}
    
    print("\n   API URL (default: http://localhost:8000)")
    url = input("   API URL: ").strip()
    settings['api_url'] = url if url else "http://localhost:8000"
    
    print("\n   User ID (default: 1)")
    user_id = input("   User ID: ").strip()
    settings['user_id'] = int(user_id) if user_id else 1
    
    print("\n   Device ID (press Enter to skip)")
    device_id = input("   Device ID: ").strip()
    settings['device_id'] = int(device_id) if device_id else None
    
    print("\n   Maximum alerts to create (default: 2000)")
    max_alerts = input("   Max alerts: ").strip()
    settings['max_alerts'] = int(max_alerts) if max_alerts else 2000
    
    print("\n   Minimum rows between alerts (default: 200)")
    gap = input("   Alert gap: ").strip()
    settings['alert_gap_rows'] = int(gap) if gap else 200
    
    print("\n   Cooldown between API calls in seconds (default: 0.25)")
    cooldown = input("   Cooldown: ").strip()
    settings['alert_cooldown'] = float(cooldown) if cooldown else 0.25
    
    return settings


def interactive_main():
    """Main interactive function"""
    print_header()
    
    mode = get_mode()
    file_path = get_file_path(mode)
    max_rows = get_max_rows()
    
    threshold = None
    alert_settings = {}
    
    if mode == "detect":
        threshold = get_threshold()
        alert_settings = get_alert_settings()
    
    # Show configuration summary
    print("\n" + "=" * 70)
    print("CONFIGURATION SUMMARY:")
    print("=" * 70)
    print(f"Mode: {mode.upper()}")
    print(f"File: {file_path}")
    print(f"Max rows: {max_rows if max_rows else 'ALL'}")
    if mode == "detect":
        print(f"Threshold: {threshold if threshold else 'AUTO'}")
        if alert_settings.get('emit_alerts'):
            print(f"Alerts: YES")
            print(f"  API URL: {alert_settings['api_url']}")
            print(f"  User ID: {alert_settings['user_id']}")
            print(f"  Device ID: {alert_settings.get('device_id', 'None')}")
            print(f"  Max alerts: {alert_settings['max_alerts']}")
        else:
            print(f"Alerts: NO")
    print("=" * 70)
    
    confirm = input("\nProceed? (y/n): ").strip().lower()
    if confirm != 'y':
        print("Cancelled")
        return
    
    # Initialize and run
    loader = CICIDSLoader(file_path, model_dir='models')
    loader.load_data(max_rows=max_rows)
    
    if mode == "train":
        print("\nTRAINING MODE")
        print("Learning normal network behavior...")
        loader.train()
        print("\nTraining completed! Model saved.")
    else:
        print("\nDETECTION MODE")
        print("Detecting anomalies...")
        loader.detect(
            threshold=threshold,
            max_samples=max_rows,
            emit_alerts=alert_settings.get('emit_alerts', False),
            api_url=alert_settings.get('api_url', 'http://localhost:8000'),
            user_id=alert_settings.get('user_id', 1),
            device_id=alert_settings.get('device_id', None),
            max_alerts=alert_settings.get('max_alerts', 2000),
            alert_gap_rows=alert_settings.get('alert_gap_rows', 200),
            alert_cooldown=alert_settings.get('alert_cooldown', 0.25),
        )
        print("\nDetection completed! Results saved.")
    
    print("\n" + "=" * 70)
    print("DONE!")
    print("=" * 70)

# -------------------------------------------------------------------
# Alert emission (dynamic alerts via your FastAPI)
# -------------------------------------------------------------------
class AlertEmitter:
    """
    Sends alerts to your backend:
      POST {api_url}/alerts/alerts
    This matches your router path: router.post("/alerts", ...) under prefix "/alerts".
    So full path becomes: /alerts/alerts
    """

    def __init__(
        self,
        api_url: str,
        user_id: int,
        device_id: Optional[int],
        timeout: int = 10,
        min_gap_rows: int = 200,
        cooldown_seconds: float = 0.25,
        max_alerts: int = 2000,
    ):
        self.api_url = api_url.rstrip("/")
        self.user_id = user_id
        self.device_id = device_id
        self.timeout = timeout
        self.min_gap_rows = min_gap_rows
        self.cooldown_seconds = cooldown_seconds
        self.max_alerts = max_alerts

        self._last_row = -10**18
        self._last_time = 0.0
        self._sent = 0
        self._failed = 0

    @staticmethod
    def severity(rmse: float, threshold: float) -> str:
        if threshold <= 0:
            return "high"
        ratio = rmse / threshold
        if ratio >= 5:
            return "critical"
        if ratio >= 3:
            return "high"
        if ratio >= 2:
            return "medium"
        return "low"

    def can_send(self, row_index: int) -> bool:
        now = time.time()
        if self._sent >= self.max_alerts:
            return False
        if (row_index - self._last_row) < self.min_gap_rows:
            return False
        if (now - self._last_time) < self.cooldown_seconds:
            return False
        return True

    def send_alert(self, payload: Dict, row_index: int) -> bool:
        if not self.can_send(row_index):
            return False

        url = f"{self.api_url}/alerts/alerts"
        payload["user_id"] = self.user_id
        payload["device_id"] = self.device_id

        try:
            r = requests.post(url, json=payload, timeout=self.timeout)
            if r.status_code in (200, 201):
                self._sent += 1
                self._last_row = row_index
                self._last_time = time.time()
                return True
            self._failed += 1
            return False
        except Exception:
            self._failed += 1
            return False

    @property
    def sent_count(self) -> int:
        return self._sent

    @property
    def failed_count(self) -> int:
        return self._failed


# -------------------------------------------------------------------
# CICIDS Loader
# -------------------------------------------------------------------
class CICIDSLoader:
    """
    Loads a preprocessed CICIDS2017 CSV and runs KitNET.
    """

    def __init__(self, csv_file: str, model_dir: str = "models"):
        self.csv_file = Path(csv_file)
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)

        # Main CICIDS flow features (you had these already)
        self.feature_columns: List[str] = [
            "Source Port",
            "Destination Port",
            "Protocol",
            "Flow Duration",
            "Total Fwd Packets",
            "Total Backward Packets",
            "Total Length of Fwd Packets",
            "Total Length of Bwd Packets",
            "Fwd Packet Length Max",
            "Fwd Packet Length Min",
            "Fwd Packet Length Mean",
            "Fwd Packet Length Std",
            "Bwd Packet Length Max",
            "Bwd Packet Length Min",
            "Bwd Packet Length Mean",
            "Bwd Packet Length Std",
            "Flow Bytes/s",
            "Flow Packets/s",
            "Fwd Packets/s",
            "Bwd Packets/s",
            "Flow IAT Mean",
            "Flow IAT Std",
            "Flow IAT Max",
            "Flow IAT Min",
            "Fwd IAT Mean",
            "Fwd IAT Std",
            "Fwd IAT Max",
            "Fwd IAT Min",
            "Bwd IAT Mean",
            "Bwd IAT Std",
            "Bwd IAT Max",
            "Bwd IAT Min",
            "FIN Flag Count",
            "SYN Flag Count",
            "RST Flag Count",
            "PSH Flag Count",
            "ACK Flag Count",
            "URG Flag Count",
            "Fwd Header Length",
            "Bwd Header Length",
            "Min Packet Length",
            "Max Packet Length",
            "Packet Length Mean",
            "Packet Length Std",
            "Active Mean",
            "Active Std",
            "Active Max",
            "Active Min",
            "Idle Mean",
            "Idle Std",
            "Idle Max",
            "Idle Min",
        ]

        self.df: Optional[pd.DataFrame] = None
        self.kitsune: Optional[KitNET] = None

        # Saved training normalization parameters:
        # X_norm = (X - min) / range, clipped to [0,1]
        self.norm_params: Optional[Dict[str, np.ndarray]] = None

        # For model saving/loading
        self.training_file: Optional[str] = None

    # -----------------------------
    # Data loading
    # -----------------------------
    def load_data(self, max_rows: Optional[int] = None) -> pd.DataFrame:
        print("=" * 70)
        print("LOADING CICIDS2017 DATA")
        print("=" * 70)
        print(f"File: {self.csv_file}")

        if not self.csv_file.exists():
            raise FileNotFoundError(f"File not found: {self.csv_file}")

        print("Reading CSV...")
        if max_rows:
            self.df = pd.read_csv(self.csv_file, nrows=max_rows)
            print(f"Loaded first {max_rows:,} rows")
        else:
            self.df = pd.read_csv(self.csv_file)
            print(f"Loaded {len(self.df):,} rows")

        print(f"Columns: {len(self.df.columns)}")

        if "Label" in self.df.columns:
            print("\nLabel Distribution:")
            label_counts = self.df["Label"].value_counts()
            total = len(self.df)
            for label, count in label_counts.items():
                pct = (count / total) * 100
                print(f"  {label:20s}: {count:8,} ({pct:5.2f}%)")

        return self.df

    # -----------------------------
    # Features & normalization
    # -----------------------------
    def _resolve_feature_columns(self) -> None:
        assert self.df is not None

        missing = [c for c in self.feature_columns if c not in self.df.columns]
        if missing:
            print(f"\nWarning: Missing {len(missing)} feature columns in this CSV.")
            for c in missing[:10]:
                print(f"  - {c}")
            if len(missing) > 10:
                print(f"  ... and {len(missing)-10} more")

            available = [c for c in self.feature_columns if c in self.df.columns]
            self.feature_columns = available

        if not self.feature_columns:
            raise ValueError("No feature columns available in CSV. Check preprocessing output.")

    def _extract_raw_matrix(self) -> np.ndarray:
        assert self.df is not None
        self._resolve_feature_columns()

        X = self.df[self.feature_columns].values
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        return X

    def fit_normalization(self, X: np.ndarray) -> np.ndarray:
        """
        Fit min-max normalization on training data and store parameters.
        """
        X_min = X.min(axis=0)
        X_max = X.max(axis=0)
        X_range = X_max - X_min
        X_range[X_range == 0] = 1.0

        self.norm_params = {"min": X_min, "range": X_range}
        return self.apply_normalization(X)

    def apply_normalization(self, X: np.ndarray) -> np.ndarray:
        """
        Apply saved min-max normalization (training params) and clip to [0,1].
        """
        if self.norm_params is None:
            raise RuntimeError("Normalization parameters not set. Train first or load a model.")

        X_min = self.norm_params["min"]
        X_range = self.norm_params["range"]

        Xn = (X - X_min) / X_range
        Xn = np.clip(Xn, 0.0, 1.0)
        return Xn

    def prepare_features_for_training(self) -> np.ndarray:
        print("\n" + "=" * 70)
        print("PREPARING FEATURES (TRAIN)")
        print("=" * 70)

        X = self._extract_raw_matrix()
        print(f"Using {len(self.feature_columns)} features")
        print(f"Feature matrix shape: {X.shape}")
        print(f"Raw feature range: [{X.min():.2f}, {X.max():.2f}]")

        print("\nNormalizing features (fit on training data)...")
        Xn = self.fit_normalization(X)

        print(f"Normalized range: [{Xn.min():.6f}, {Xn.max():.6f}]")
        print(f"Mean: {Xn.mean():.6f}, Std: {Xn.std():.6f}")
        return Xn

    def prepare_features_for_detection(self) -> np.ndarray:
        print("\n" + "=" * 70)
        print("PREPARING FEATURES (DETECT)")
        print("=" * 70)

        X = self._extract_raw_matrix()
        print(f"Using {len(self.feature_columns)} features")
        print(f"Feature matrix shape: {X.shape}")
        print(f"Raw feature range: [{X.min():.2f}, {X.max():.2f}]")

        print("\nNormalizing features (using training parameters)...")
        Xn = self.apply_normalization(X)

        print(f"Normalized range: [{Xn.min():.6f}, {Xn.max():.6f}]")
        print(f"Mean: {Xn.mean():.6f}, Std: {Xn.std():.6f}")
        return Xn

    # -----------------------------
    # Grace periods
    # -----------------------------
    @staticmethod
    def calculate_grace_periods(n_samples: int) -> Tuple[int, int]:
        """
        - FM_grace: 5% (min 1000, max 20000)
        - AD_grace: 65% of total
        """
        fm_grace = max(1000, min(20000, int(n_samples * 0.05)))
        ad_grace = int(n_samples * 0.65)

        detection_samples = n_samples - ad_grace
        det_pct = (detection_samples / n_samples) * 100

        print("\nAutomatic Grace Period Configuration:")
        print(f"  Total samples: {n_samples:,}")
        print(f"  FM grace:      {fm_grace:,} ({fm_grace/n_samples*100:.1f}%)")
        print(f"  AD grace:      {ad_grace:,} ({ad_grace/n_samples*100:.1f}%)")
        print(f"  Detection:     {detection_samples:,} ({det_pct:.1f}%)")
        print("  Note: RMSE scores appear only after AD grace is over.")

        if det_pct < 10:
            print("Warning: Detection portion is < 10%. Consider training with more samples.")

        return fm_grace, ad_grace

    # -----------------------------
    # Train
    # -----------------------------
    def train(
        self,
        max_autoencoder_size: int = 10,
        FM_grace_period: Optional[int] = None,
        AD_grace_period: Optional[int] = None,
        learning_rate: float = 0.1,
        hidden_ratio: float = 0.75,
    ) -> np.ndarray:
        assert self.df is not None

        print("\n" + "=" * 70)
        print("TRAINING KITSUNE")
        print("=" * 70)

        X = self.prepare_features_for_training()
        n_samples, n_features = X.shape

        if FM_grace_period is None or AD_grace_period is None:
            fm_grace, ad_grace = self.calculate_grace_periods(n_samples)
        else:
            fm_grace, ad_grace = FM_grace_period, AD_grace_period
            print("\nUsing manual grace periods:")
            print(f"  FM grace: {fm_grace:,}")
            print(f"  AD grace: {ad_grace:,}")

        print("\nTraining Configuration:")
        print(f"  Samples: {n_samples:,}")
        print(f"  Features: {n_features}")
        print(f"  Max Autoencoder Size: {max_autoencoder_size}")
        print(f"  Learning Rate: {learning_rate}")
        print(f"  Hidden Ratio: {hidden_ratio}")

        print("\nInitializing KitNET...")
        self.kitsune = KitNET(
            n_features,
            max_autoencoder_size=max_autoencoder_size,
            FM_grace_period=fm_grace,
            AD_grace_period=ad_grace,
            learning_rate=learning_rate,
            hidden_ratio=hidden_ratio,
        )
        print("KitNET initialized")

        rmse_scores: List[float] = []
        start_time = datetime.now()

        print(f"\nTraining on {n_samples:,} samples...")
        for i in range(n_samples):
            rmse = self.kitsune.process(X[i])
            rmse_scores.append(float(rmse) if rmse is not None else 0.0)

            if (i + 1) % 10000 == 0:
                elapsed = (datetime.now() - start_time).total_seconds()
                rate = (i + 1) / max(elapsed, 1e-9)
                remaining = (n_samples - i - 1) / max(rate, 1e-9) / 60.0
                pct = (i + 1) / n_samples * 100

                print(
                    f"  [{i+1:,}/{n_samples:,}] ({pct:.1f}%) | "
                    f"Speed: {rate:.0f} samples/sec | ETA: {remaining:.1f} min"
                )

                recent = np.array(rmse_scores[-1000:], dtype=float)
                nz = recent[recent > 0]
                if nz.size > 0:
                    print(
                        f"    Recent RMSE: mean={nz.mean():.6f}, std={nz.std():.6f}, max={nz.max():.6f}"
                    )
                else:
                    print("    RMSE: still in grace/training phase (zeros)")

        elapsed_total = (datetime.now() - start_time).total_seconds() / 60.0
        print(f"\nTraining completed in {elapsed_total:.2f} minutes")

        rmse_arr = np.array(rmse_scores, dtype=float)
        non_zero = rmse_arr[rmse_arr > 0]

        threshold = None
        print("\nTraining RMSE Statistics:")
        print(f"  Total RMSE values: {rmse_arr.size:,}")
        print(f"  Non-zero values:   {non_zero.size:,} ({(non_zero.size/rmse_arr.size*100 if rmse_arr.size else 0):.1f}%)")

        if non_zero.size > 0:
            print(f"  Mean:   {non_zero.mean():.6f}")
            print(f"  Std:    {non_zero.std():.6f}")
            print(f"  Min:    {non_zero.min():.6f}")
            print(f"  Max:    {non_zero.max():.6f}")
            print(f"  Median: {np.median(non_zero):.6f}")

            threshold = float(non_zero.mean() + 3.0 * non_zero.std())
            print(f"\nSuggested Anomaly Threshold: {threshold:.6f}")
        else:
            print("Warning: All RMSE scores are zero. Model never entered execute phase.")
            print("Possible causes:")
            print("  1) AD_grace_period >= total samples")
            print("  2) Training set too small")
            print("  3) Feature issues after preprocessing")

        self.training_file = str(self.csv_file)
        self.save_model(training_scores=rmse_arr, threshold=threshold)

        return rmse_arr

    # -----------------------------
    # Threshold calibration
    # -----------------------------
    @staticmethod
    def _threshold_mean_3std(scores: np.ndarray) -> Optional[float]:
        nz = scores[scores > 0]
        if nz.size == 0:
            return None
        return float(nz.mean() + 3.0 * nz.std())

    def calibrate_threshold_on_benign(
        self,
        X: np.ndarray,
        labels: np.ndarray,
        n_benign: int = 20000,
        skip_first: int = 1000,
    ) -> Optional[float]:
        """
        Calibrate threshold using BENIGN rows inside the detect file.
        This is useful when your saved threshold does not generalize well.

        Procedure:
        - Take up to n_benign BENIGN samples
        - Skip the first 'skip_first' benign to avoid warmup bias
        - Compute threshold = mean + 3*std on their RMSE (non-zero)
        """
        if self.kitsune is None:
            raise RuntimeError("Model not loaded.")

        if labels is None:
            return None

        benign_idx = np.where(labels == "BENIGN")[0]
        if benign_idx.size == 0:
            print("Calibration skipped: no BENIGN rows in this detect file.")
            return None

        take = min(n_benign, benign_idx.size)
        benign_idx = benign_idx[:take]

        rmse_list = []
        for j, i in enumerate(benign_idx):
            rmse = self.kitsune.process(X[i])
            rmse_list.append(float(rmse) if rmse is not None else 0.0)

        scores = np.array(rmse_list, dtype=float)
        if scores.size <= skip_first:
            return None

        scores2 = scores[skip_first:]
        thr = self._threshold_mean_3std(scores2)
        if thr is None:
            return None

        print("\nThreshold Calibration (BENIGN in detect file):")
        print(f"  BENIGN used: {scores2.size:,} (skipped first {skip_first})")
        nz = scores2[scores2 > 0]
        if nz.size > 0:
            print(f"  RMSE mean: {nz.mean():.6f}")
            print(f"  RMSE std:  {nz.std():.6f}")
            print(f"  RMSE min:  {nz.min():.6f}")
            print(f"  RMSE max:  {nz.max():.6f}")
        print(f"  Calibrated threshold: {thr:.6f}")

        return thr

    # -----------------------------
    # Detect
    # -----------------------------
    def detect(
        self,
        threshold: Optional[float] = None,
        max_samples: Optional[int] = None,
        calibrate_benign: Optional[int] = None,
        emit_alerts: bool = False,
        api_url: str = "http://localhost:8000",
        user_id: int = 1,
        device_id: Optional[int] = None,
        max_alerts: int = 2000,
        alert_gap_rows: int = 200,
        alert_cooldown: float = 0.25,
    ) -> Tuple[np.ndarray, np.ndarray]:
        assert self.df is not None

        print("\n" + "=" * 70)
        print("DETECTING ANOMALIES")
        print("=" * 70)

        if self.kitsune is None:
            saved_threshold = self.load_model()
            if threshold is None and saved_threshold is not None:
                threshold = float(saved_threshold)

        X = self.prepare_features_for_detection()

        total_rows = X.shape[0]
        n_samples = total_rows if max_samples is None else min(total_rows, int(max_samples))
        X = X[:n_samples]

        labels = None
        if "Label" in self.df.columns:
            labels = self.df["Label"].values[:n_samples]

        print("\nDetection Configuration:")
        print(f"  Samples to process: {n_samples:,}")
        print(f"  Threshold: {threshold:.6f}" if threshold is not None else "  Threshold: auto")

        emitter = None
        if emit_alerts:
            emitter = AlertEmitter(
                api_url=api_url,
                user_id=int(user_id),
                device_id=device_id,
                min_gap_rows=int(alert_gap_rows),
                cooldown_seconds=float(alert_cooldown),
                max_alerts=int(max_alerts),
            )
            print("\nDynamic Alert Emission:")
            print(f"  API URL: {api_url}")
            print(f"  user_id: {user_id}")
            print(f"  device_id: {device_id}")
            print(f"  max_alerts: {max_alerts}")
            print(f"  alert_gap_rows: {alert_gap_rows}")
            print(f"  alert_cooldown: {alert_cooldown}")

        # If threshold not given, compute a fallback from this run after collecting rmse
        rmse_scores = np.zeros(n_samples, dtype=float)

        start_time = datetime.now()
        print(f"\nProcessing {n_samples:,} samples...")

        for i in range(n_samples):
            rmse = self.kitsune.process(X[i])
            rmse_scores[i] = float(rmse) if rmse is not None else 0.0

            if (i + 1) % 10000 == 0:
                elapsed = (datetime.now() - start_time).total_seconds()
                rate = (i + 1) / max(elapsed, 1e-9)
                remaining = (n_samples - i - 1) / max(rate, 1e-9) / 60.0
                pct = (i + 1) / n_samples * 100
                print(
                    f"  [{i+1:,}/{n_samples:,}] ({pct:.1f}%) | "
                    f"Speed: {rate:.0f} samples/sec | ETA: {remaining:.1f} min"
                )

        elapsed_total = (datetime.now() - start_time).total_seconds() / 60.0
        print(f"\nDetection completed in {elapsed_total:.2f} minutes")

        # Optional calibration on BENIGN inside the detect file
        # IMPORTANT: Calibration should be done BEFORE classifying anomalies.
        # We already processed full file once above, so calibration must NOT call process() again on same KitNET
        # because KitNET execute-mode updates internal state (though typically in execute it doesn't train, but to be safe).
        # Therefore: for calibration we recommend providing threshold manually OR running detect with --max-rows on benign subset.
        #
        # However, many KitNET implementations do not update weights in execute-mode; still, double pass can shift behavior.
        # So here we do a safer approach:
        # - If user asks calibrate_benign, we compute threshold from *observed RMSE* of BENIGN rows from this pass.
        if calibrate_benign is not None and labels is not None:
            benign_mask = (labels == "BENIGN")
            benign_scores = rmse_scores[benign_mask]
            if benign_scores.size > 0:
                take = min(int(calibrate_benign), benign_scores.size)
                benign_scores = benign_scores[:take]
                # skip warmup
                skip_first = min(1000, max(0, take // 10))
                benign_scores2 = benign_scores[skip_first:]
                thr2 = self._threshold_mean_3std(benign_scores2)
                if thr2 is not None:
                    print("\nThreshold Calibration (BENIGN from observed RMSE):")
                    print(f"  BENIGN available: {int(benign_mask.sum()):,}")
                    print(f"  BENIGN used:      {take:,} (skipped first {skip_first})")
                    nz = benign_scores2[benign_scores2 > 0]
                    if nz.size > 0:
                        print(f"  RMSE mean: {nz.mean():.6f}")
                        print(f"  RMSE std:  {nz.std():.6f}")
                        print(f"  RMSE min:  {nz.min():.6f}")
                        print(f"  RMSE max:  {nz.max():.6f}")
                    print(f"  Calibrated threshold: {thr2:.6f}")
                    threshold = float(thr2)

        if threshold is None:
            thr_auto = self._threshold_mean_3std(rmse_scores)
            threshold = float(thr_auto) if thr_auto is not None else 0.001
            print(f"\nAuto-calculated threshold: {threshold:.6f}")

        predictions = (rmse_scores > threshold).astype(int)

        n_anomalies = int(predictions.sum())
        print("\nDetection Results:")
        print(f"  Total samples:       {n_samples:,}")
        print(f"  Detected anomalies:  {n_anomalies:,} ({(n_anomalies/n_samples*100 if n_samples else 0):.2f}%)")
        print(f"  Normal samples:      {n_samples - n_anomalies:,} ({((n_samples-n_anomalies)/n_samples*100 if n_samples else 0):.2f}%)")

        # RMSE stats
        print(f"\nThreshold used: {threshold:.6f}")
        print(
            f"RMSE stats: mean={rmse_scores.mean():.6f}, std={rmse_scores.std():.6f}, "
            f"min={rmse_scores.min():.6f}, max={rmse_scores.max():.6f}"
        )

        # Metrics if labels exist
        if labels is not None:
            self.calculate_metrics(labels, predictions)

        # Emit alerts dynamically
        if emit_alerts and emitter is not None:
            self.emit_alerts_from_predictions(
                emitter=emitter,
                rmse_scores=rmse_scores,
                predictions=predictions,
                threshold=float(threshold),
                labels=labels,
            )
            print(f"\nDynamic alerts created in DB: {emitter.sent_count}")
            if emitter.failed_count > 0:
                print(f"Dynamic alert POST failures: {emitter.failed_count}")

        # Save detection results
        self.save_detection_results(rmse_scores, predictions, labels, threshold)

        return rmse_scores, predictions

    def emit_alerts_from_predictions(
        self,
        emitter: AlertEmitter,
        rmse_scores: np.ndarray,
        predictions: np.ndarray,
        threshold: float,
        labels: Optional[np.ndarray],
    ) -> None:
        """
        Create alerts dynamically in your DB through your FastAPI endpoint.
        Tries to include Source IP / Destination IP if present in CSV.
        """
        assert self.df is not None

        # These columns exist in many CICIDS preprocessed exports
        src_ip_col = "Source IP" if "Source IP" in self.df.columns else None
        dst_ip_col = "Destination IP" if "Destination IP" in self.df.columns else None

        sent_before = emitter.sent_count
        attack_anomalies = 0
        benign_filtered = 0  # Track how many BENIGN we filtered out


        for i in range(len(predictions)):
            if predictions[i] != 1:
                continue

            if labels is not None:
             if labels[i] == "BENIGN":
                benign_filtered += 1
                continue  # Skip to next iteration - NO ALERT FOR BENIGN
             
            attack_anomalies += 1
            rmse = float(rmse_scores[i])
            sev = emitter.severity(rmse, threshold)

            src_ip = str(self.df.iloc[i][src_ip_col]) if src_ip_col else None
            dst_ip = str(self.df.iloc[i][dst_ip_col]) if dst_ip_col else None

            true_label = str(labels[i]) if labels is not None else None

            details = {
                "file": str(self.csv_file),
                "row_index": int(i),
                "true_label": true_label,
                "threshold": float(threshold),
                "rmse": rmse,
            }

            # extra context if available
            for col in ["Source Port", "Destination Port", "Protocol", "Flow Duration"]:
                if col in self.df.columns:
                    val = self.df.iloc[i][col]
                    try:
                        details[col] = float(val) if "Duration" in col else int(val)
                    except Exception:
                        details[col] = str(val)

            payload = {
                "title": "Network anomaly detected",
                "message": f"RMSE={rmse:.6f} exceeded threshold={threshold:.6f}",
                "severity": sev,
                "status": "active",
                "acknowledged": False,
                "source_ip": src_ip,
                "dest_ip": dst_ip,
                "rmse_score": rmse,
                "details": json.dumps(details),
            }

            emitter.send_alert(payload, row_index=i)

        sent_after = emitter.sent_count
        created = sent_after - sent_before
        print(f"\nAlerts attempted from anomalies: {int(predictions.sum()):,}")
        print(f"Alerts actually created (throttled): {created:,}")

    # -----------------------------
    # Metrics
    # -----------------------------
    def calculate_metrics(self, true_labels: np.ndarray, predictions: np.ndarray) -> None:
        print("\n" + "=" * 70)
        print("EVALUATION METRICS")
        print("=" * 70)

        y_true = (true_labels != "BENIGN").astype(int)
        y_pred = predictions.astype(int)

        TP = int(np.sum((y_true == 1) & (y_pred == 1)))
        TN = int(np.sum((y_true == 0) & (y_pred == 0)))
        FP = int(np.sum((y_true == 0) & (y_pred == 1)))
        FN = int(np.sum((y_true == 1) & (y_pred == 0)))

        print("\nConfusion Matrix:")
        print(f"  True Positives (TP): {TP:8,} | Correctly detected attacks")
        print(f"  True Negatives (TN): {TN:8,} | Correctly identified normal")
        print(f"  False Positives (FP):{FP:8,} | False alarms")
        print(f"  False Negatives (FN):{FN:8,} | Missed attacks")

        total = TP + TN + FP + FN
        accuracy = (TP + TN) / total if total else 0.0
        precision = TP / (TP + FP) if (TP + FP) else 0.0
        recall = TP / (TP + FN) if (TP + FN) else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) else 0.0
        fpr = FP / (FP + TN) if (FP + TN) else 0.0

        print("\nPerformance Metrics:")
        print(f"  Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
        print(f"  Precision: {precision:.4f} ({precision*100:.2f}%)")
        print(f"  Recall:    {recall:.4f} ({recall*100:.2f}%)")
        print(f"  F1-Score:  {f1:.4f}")
        print(f"  FPR:       {fpr:.4f} ({fpr*100:.2f}%)")

        print("\nPer-Class Detection:")
        for label in np.unique(true_labels):
            mask = (true_labels == label)
            n = int(mask.sum())
            detected = int(predictions[mask].sum())
            rate = (detected / n * 100) if n else 0.0
            print(f"  {label:20s}: {detected:6,}/{n:6,} detected ({rate:5.2f}%)")

    # -----------------------------
    # Save/Load
    # -----------------------------
    def save_model(self, training_scores: Optional[np.ndarray] = None, threshold: Optional[float] = None) -> None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        model_name = f"kitsune_model_{timestamp}.pkl"
        model_path = self.model_dir / model_name

        print(f"\nSaving model to: {model_path}")

        model_data = {
            "kitsune": self.kitsune,
            "feature_columns": self.feature_columns,
            "norm_params": self.norm_params,
            "training_file": str(self.csv_file),
            "timestamp": timestamp,
            "threshold": threshold,
        }

        if training_scores is not None:
            model_data["training_scores"] = training_scores

        with open(model_path, "wb") as f:
            pickle.dump(model_data, f)

        latest_path = self.model_dir / "kitsune_latest.pkl"
        with open(latest_path, "wb") as f:
            pickle.dump(model_data, f)

        print("Model saved successfully")
        print(f"Latest model updated: {latest_path}")

    def load_model(self, model_path: Optional[str] = None) -> Optional[float]:
        if model_path is None:
            model_path = str(self.model_dir / "kitsune_latest.pkl")

        model_path = Path(model_path)
        print(f"\nLoading model from: {model_path}")

        if not model_path.exists():
            raise FileNotFoundError(f"Model not found: {model_path}")

        with open(model_path, "rb") as f:
            model_data = pickle.load(f)

        self.kitsune = model_data["kitsune"]
        self.feature_columns = model_data["feature_columns"]
        self.norm_params = model_data.get("norm_params", None)
        self.training_file = model_data.get("training_file", None)

        print("Model loaded successfully")
        print(f"Trained on: {self.training_file}")
        print(f"Timestamp: {model_data.get('timestamp', 'Unknown')}")
        print(f"Features: {len(self.feature_columns)}")
        print(f"Normalization saved: {'Yes' if self.norm_params is not None else 'No'}")

        threshold = model_data.get("threshold", None)
        if threshold is not None:
            print(f"Saved threshold: {threshold:.6f}")

        return threshold

    # -----------------------------
    # Save detection results
    # -----------------------------
    def save_detection_results(
        self,
        scores: np.ndarray,
        predictions: np.ndarray,
        labels: Optional[np.ndarray] = None,
        threshold: Optional[float] = None,
    ) -> None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_file = self.model_dir / f"detection_results_{timestamp}.csv"

        print(f"\nSaving results to: {results_file}")

        results_df = pd.DataFrame(
            {
                "RMSE_Score": scores.astype(float),
                "Prediction": np.where(predictions == 1, "ANOMALY", "NORMAL"),
            }
        )

        if labels is not None:
            results_df["True_Label"] = labels
            results_df["Correct"] = (
                ((labels == "BENIGN") & (predictions == 0)) | ((labels != "BENIGN") & (predictions == 1))
            )

        results_df.to_csv(results_file, index=False)

        summary_file = self.model_dir / f"detection_summary_{timestamp}.json"
        summary = {
            "file": str(self.csv_file),
            "timestamp": timestamp,
            "total_samples": int(len(scores)),
            "anomalies_detected": int(np.sum(predictions)),
            "threshold": float(threshold) if threshold is not None else None,
            "mean_score": float(np.mean(scores)),
            "std_score": float(np.std(scores)),
            "min_score": float(np.min(scores)),
            "max_score": float(np.max(scores)),
        }

        if labels is not None:
            y_true = (labels != "BENIGN").astype(int)
            y_pred = predictions.astype(int)

            TP = int(np.sum((y_true == 1) & (y_pred == 1)))
            TN = int(np.sum((y_true == 0) & (y_pred == 0)))
            FP = int(np.sum((y_true == 0) & (y_pred == 1)))
            FN = int(np.sum((y_true == 1) & (y_pred == 0)))

            total = TP + TN + FP + FN
            accuracy = (TP + TN) / total if total else 0.0
            precision = TP / (TP + FP) if (TP + FP) else 0.0
            recall = TP / (TP + FN) if (TP + FN) else 0.0
            f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) else 0.0

            summary["metrics"] = {
                "TP": TP,
                "TN": TN,
                "FP": FP,
                "FN": FN,
                "accuracy": float(accuracy),
                "precision": float(precision),
                "recall": float(recall),
                "f1_score": float(f1),
            }

        with open(summary_file, "w") as f:
            json.dump(summary, f, indent=2)

        print("Results saved")
        print(f"Summary saved to: {summary_file}")


# -------------------------------------------------------------------
# CLI
# -------------------------------------------------------------------
def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="CICIDS2017 Loader for Kitsune IDS (KitNET)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument("--interactive", action="store_true", help="Run in interactive mode")
    p.add_argument("--mode", type=str, required=False, choices=["train", "detect"], help="train or detect")
    p.add_argument("--file", type=str, required=False, help="Path to preprocessed CICIDS CSV file")
    p.add_argument("--model-dir", type=str, default="models", help="Directory to save/load models")
    p.add_argument("--max-rows", type=int, default=None, help="Maximum rows to process")

    # Train options
    p.add_argument("--max-ae-size", type=int, default=10, help="Max autoencoder size")
    p.add_argument("--fm-grace", type=int, default=None, help="FM grace period (optional)")
    p.add_argument("--ad-grace", type=int, default=None, help="AD grace period (optional)")
    p.add_argument("--learning-rate", type=float, default=0.1, help="Learning rate")
    p.add_argument("--hidden-ratio", type=float, default=0.75, help="Hidden ratio")

    # Detect options
    p.add_argument("--threshold", type=float, default=None, help="Anomaly threshold (optional)")
    p.add_argument("--calibrate-benign", type=int, default=None, help="Calibrate threshold using N BENIGN rows from detect file")

    # Dynamic alerts
    p.add_argument("--emit-alerts", action="store_true", help="Create alerts dynamically via API")
    p.add_argument("--api-url", type=str, default="http://localhost:8000", help="Backend API URL")
    p.add_argument("--user-id", type=int, default=1, help="user_id for created alerts")
    p.add_argument("--device-id", type=int, default=None, help="device_id for created alerts")
    p.add_argument("--max-alerts", type=int, default=2000, help="Max alerts to create (throttled)")
    p.add_argument("--alert-gap-rows", type=int, default=200, help="Minimum row gap between alerts")
    p.add_argument("--alert-cooldown", type=float, default=0.25, help="Cooldown seconds between alerts")

    return p


def main() -> None:
    args = build_arg_parser().parse_args()

    # Check for interactive mode first
    if args.interactive:
        interactive_main()
        return

    # Validate command-line mode requirements
    if not args.mode or not args.file:
        print("Error: --mode and --file are required for command-line mode")
        print("Use --interactive for interactive mode")
        return

    # Your original code continues here...
    print("=" * 70)
    print("CICIDS2017 LOADER FOR KITSUNE IDS")
    # ... everything else stays the same

    print("=" * 70)
    print("CICIDS2017 LOADER FOR KITSUNE IDS")
    print("=" * 70)
    print(f"Mode: {args.mode.upper()}")
    print(f"File: {args.file}")
    if args.max_rows:
        print(f"Max rows: {args.max_rows:,}")
    print("=" * 70)

    loader = CICIDSLoader(args.file, model_dir=args.model_dir)
    loader.load_data(max_rows=args.max_rows)

    if args.mode == "train":
        print("\nTRAINING MODE")
        print("Learning normal network behavior...")

        loader.train(
            max_autoencoder_size=args.max_ae_size,
            FM_grace_period=args.fm_grace,
            AD_grace_period=args.ad_grace,
            learning_rate=args.learning_rate,
            hidden_ratio=args.hidden_ratio,
        )

        print("\nTraining completed. Model saved.")
        print("Next steps:")
        print("  1) Run detection on Friday DDoS or PortScan")
        print("  2) If results look bad, try --calibrate-benign 20000")

    else:
        print("\nDETECTION MODE")
        print("Detecting anomalies...")

        loader.detect(
            threshold=args.threshold,
            max_samples=args.max_rows,
            calibrate_benign=args.calibrate_benign,
            emit_alerts=args.emit_alerts,
            api_url=args.api_url,
            user_id=args.user_id,
            device_id=args.device_id,
            max_alerts=args.max_alerts,
            alert_gap_rows=args.alert_gap_rows,
            alert_cooldown=args.alert_cooldown,
        )

        print("\nDetection completed. Results saved.")
        print("Check:")
        print(f"  - {args.model_dir}/detection_results_*.csv")
        print(f"  - {args.model_dir}/detection_summary_*.json")

        if args.emit_alerts:
            print("\nDynamic alerts were emitted via API.")
            print("View alerts:")
            print(f"  GET {args.api_url}/alerts/alerts/user/{args.user_id}")

    print("\n" + "=" * 70)
    print("DONE")
    print("=" * 70)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user")
    except Exception as e:
        print(f"\nError: {e}")
        import traceback

        traceback.print_exc()
