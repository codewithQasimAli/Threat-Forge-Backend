import sys
import os
import pandas as pd
import numpy as np
import pickle
from pathlib import Path
from datetime import datetime

current_dir = Path(__file__).parent
app_dir = current_dir.parent
root_dir = app_dir.parent
kitsune_path = root_dir / "services" / "Kitsune-py"
sys.path.insert(0, str(kitsune_path))
sys.path.insert(0, str(root_dir))

BENIGN_FILE = str(root_dir / "datasets" / "CICIDS2017" / "preprocessed" / "Monday-WorkingHours.pcap_ISCX_preprocessed.csv")
MODEL_PATH = str(root_dir / "models" / "kitsune_latest.pkl")

FEATURE_COLUMNS = [
    "Source Port","Destination Port","Protocol","Flow Duration",
    "Total Fwd Packets","Total Backward Packets",
    "Total Length of Fwd Packets","Total Length of Bwd Packets",
    "Fwd Packet Length Max","Fwd Packet Length Min","Fwd Packet Length Mean","Fwd Packet Length Std",
    "Bwd Packet Length Max","Bwd Packet Length Min","Bwd Packet Length Mean","Bwd Packet Length Std",
    "Flow Bytes/s","Flow Packets/s","Fwd Packets/s","Bwd Packets/s",
    "Flow IAT Mean","Flow IAT Std","Flow IAT Max","Flow IAT Min",
    "Fwd IAT Mean","Fwd IAT Std","Fwd IAT Max","Fwd IAT Min",
    "Bwd IAT Mean","Bwd IAT Std","Bwd IAT Max","Bwd IAT Min",
    "FIN Flag Count","SYN Flag Count","RST Flag Count","PSH Flag Count","ACK Flag Count","URG Flag Count",
    "Fwd Header Length","Bwd Header Length",
    "Min Packet Length","Max Packet Length","Packet Length Mean","Packet Length Std",
    "Active Mean","Active Std","Active Max","Active Min",
    "Idle Mean","Idle Std","Idle Max","Idle Min"
]

def load_benign_logs(user_id: str = "1", max_rows: int = 200):
    print(f"Loading benign data for user_id={user_id}, max_rows={max_rows}")

    with open(MODEL_PATH, "rb") as f:
        model_data = pickle.load(f)

    kitsune = model_data["kitsune"]
    norm_params = model_data["norm_params"]
    threshold = model_data.get("threshold", 0.000007)

    print(f"Model loaded. Threshold: {threshold:.6f}")

    df = pd.read_csv(BENIGN_FILE, encoding="utf-8", low_memory=False)
    df.columns = df.columns.str.strip()

    available = [c for c in FEATURE_COLUMNS if c in df.columns]
    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        print(f"Missing columns: {missing[:5]}...")

    df_benign = df[df["Label"].str.strip().str.upper() == "BENIGN"].head(max_rows)
    print(f"Processing {len(df_benign)} benign flows...")

    from app.database import SessionLocal
    from app.models.network_log import NetworkLog

    db = SessionLocal()
    saved = 0

    for idx, row in df_benign.iterrows():
        try:
            features = []
            for col in FEATURE_COLUMNS:
                if col in row.index:
                    val = row[col]
                    if pd.isna(val) or val == float('inf') or val == float('-inf'):
                        val = 0.0
                    features.append(float(val))
                else:
                    features.append(0.0)

            X = np.array(features, dtype=np.float64)
            min_vals = norm_params["min"]
            range_vals = norm_params["range"]
            if min_vals.shape[0] == X.shape[0]:
                Xn = (X - min_vals) / (range_vals + 1e-10)
            else:
                Xn = X
            Xn = np.clip(Xn, 0.0, 1.0)

            rmse = float(kitsune.process(Xn))
            is_anomaly = False

            severity = "none"

            log = NetworkLog(
                user_id=user_id,
                simulation_run_id="benign-cicids2017",
                src_ip=str(row.get("Source IP", row.get(" Source IP", "10.0.0.1"))).strip() if "Source IP" in row.index or " Source IP" in row.index else "10.0.0.1",
                dst_ip=str(row.get("Destination IP", row.get(" Destination IP", "10.0.0.2"))).strip() if "Destination IP" in row.index or " Destination IP" in row.index else "10.0.0.2",
                src_port=int(row.get("Source Port", 0)),
                dst_port=int(row.get("Destination Port", 0)),
                protocol=int(row.get("Protocol", 0)),
                flow_duration=float(row.get("Flow Duration", 0)),
                packet_count=int(row.get("Total Fwd Packets", 0)) + int(row.get("Total Backward Packets", 0)),
                rmse_score=rmse,
                is_anomaly=is_anomaly,
                severity=severity,
                timestamp=datetime.utcnow()
            )
            db.add(log)
            saved += 1

            if saved % 50 == 0:
                db.commit()
                print(f"  Saved {saved} flows...")

        except Exception as e:
            continue

    db.commit()
    db.close()
    print(f"Done. Saved {saved} benign flows to network_logs for user_id={user_id}")
    return saved

if __name__ == "__main__":
    uid = sys.argv[1] if len(sys.argv) > 1 else "1"
    rows = int(sys.argv[2]) if len(sys.argv) > 2 else 200
    load_benign_logs(user_id=uid, max_rows=rows)
