"""
ThreatForge — Benign Threshold Calibration Script

Recalibrates the Kitsune anomaly-detection threshold using live benign IoT
traffic captured from GNS3. The model weights are NOT changed — only the
'threshold' field in the .pkl is updated using the mu+3*sigma rule on the
observed benign RMSE distribution.

Usage:
    venv\\Scripts\\python app/services/calibrate_threshold.py
    venv\\Scripts\\python app/services/calibrate_threshold.py --capture-duration 120
"""

import argparse
import json
import os
import pickle
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path

import numpy as np

# ---------------------------------------------------------------------------
# Path setup — must happen before any app imports
# ---------------------------------------------------------------------------
_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(_ROOT))

from app.services.run_simulation import GNS3Client, KaliAttacker, MODEL_PATH
from app.services.pcap_to_features import extract_features_from_pcap

MODEL_PATH_ABS = (_ROOT / MODEL_PATH).resolve()

# Kali/attacker subnet — kept for reference
KALI_SUBNET_PREFIX = "192.168.231."

# IoT device targets
SMART_CAMERA_IP     = "192.168.56.10"
SMART_THERMOSTAT_IP = "192.168.56.20"
SMART_LOCK_IP       = "192.168.56.30"


# ---------------------------------------------------------------------------
# Kali SSH traffic generation
# ---------------------------------------------------------------------------

def generate_benign_traffic_from_kali() -> bool:
    """
    SSH into Kali, write a shell script that fires hping3 across ports,
    then execute it. One SSH session, no quote-escape issues.
    """
    print("  Generating benign UDP traffic from Kali (via SSH)...")
    attacker = KaliAttacker()
    if not attacker.connect():
        print("  ERROR: Cannot SSH to Kali. Is the VM running and reachable?")
        return False

    # Three target IoT IPs, 40 distinct ports per target = 120 unique flows total
    targets = [
        (SMART_CAMERA_IP,     5000, 5049),
        (SMART_THERMOSTAT_IP, 5100, 5149),
        (SMART_LOCK_IP,       5200, 5249),
    ]

    # Build a plain shell script as a string. No bash -c wrapping needed.
    script_lines = [
        "#!/bin/bash",
        "# No set -e — we want all iterations to run even if individual hping3 calls exit non-zero",
        "# (hping3 may return non-zero on ICMP port-unreachable replies from target)",
    ]
    for target_ip, port_start, port_end in targets:
        # Reset counters at the start of each target so the "Finished" line shows per-target values
        script_lines.append("SENT=0")
        script_lines.append("FAILED=0")
        script_lines.append(f"for port in $(seq {port_start} {port_end}); do")
        script_lines.append(
            f"  if echo 'kali' | sudo -S hping3 --udp -p $port -c 1 --data 64 {target_ip} > /dev/null 2>&1; then"
        )
        script_lines.append("    SENT=$((SENT+1))")
        script_lines.append("  else")
        script_lines.append("    FAILED=$((FAILED+1))")
        script_lines.append("  fi")
        script_lines.append("  sleep 0.05")
        script_lines.append("done")
        script_lines.append(f"echo \"Finished {target_ip} — sent:$SENT failed:$FAILED\"")
    script_content = "\n".join(script_lines) + "\n"

    remote_script = "/tmp/threatforge_benign.sh"

    try:
        # SFTP the script to Kali
        sftp = attacker._client.open_sftp()
        with sftp.file(remote_script, "w") as f:
            f.write(script_content)
        sftp.chmod(remote_script, 0o755)
        sftp.close()
        print(f"  Shell script uploaded to Kali: {remote_script}")

        # Run the script with one exec_command
        print("  Running hping3 batch on Kali — this takes ~10s...")
        stdin, stdout, stderr = attacker._client.exec_command(
            f"bash {remote_script}", timeout=120
        )
        output = stdout.read().decode(errors="replace")
        err    = stderr.read().decode(errors="replace")

        if output.strip():
            for line in output.strip().splitlines():
                print(f"  [Kali] {line}")
        if err.strip():
            # hping3 emits HPING banner lines on stderr even on success — filter those
            err_lines = [
                l for l in err.strip().splitlines()
                if ("HPING" not in l and "len=" not in l and "round-trip" not in l and l.strip())
            ]
            for line in err_lines[:5]:  # cap noise
                print(f"  [Kali stderr] {line}")

        # Cleanup
        try:
            sftp = attacker._client.open_sftp()
            sftp.remove(remote_script)
            sftp.close()
        except Exception:
            pass

        print("  Kali traffic generation complete.")
    except Exception as exc:
        print(f"  ERROR during Kali execution: {exc}")
        attacker.disconnect()
        return False

    attacker.disconnect()
    return True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _countdown(total_seconds: int, interval: int = 15) -> None:
    """Sleep for total_seconds, printing remaining time every interval seconds."""
    remaining = total_seconds
    while remaining > 0:
        print(f"  {remaining}s remaining...")
        sleep_for = min(interval, remaining)
        time.sleep(sleep_for)
        remaining -= sleep_for


def _is_kali_flow(flow: dict) -> bool:
    src = flow.get("src_ip", "")
    dst = flow.get("dst_ip", "")
    return src.startswith(KALI_SUBNET_PREFIX) or dst.startswith(KALI_SUBNET_PREFIX)


# ---------------------------------------------------------------------------
# Main calibration routine
# ---------------------------------------------------------------------------

def calibrate(capture_duration: int = 90) -> None:
    print("=" * 60)
    print("THREATFORGE — BENIGN THRESHOLD CALIBRATION")
    print("=" * 60)

    # ------------------------------------------------------------------ #
    # 1. Connect to GNS3 and start capture
    # ------------------------------------------------------------------ #
    print("\nConnecting to GNS3...")
    try:
        gns3 = GNS3Client()
        project_id = gns3.get_project_id()
        print(f"  GNS3 project found: {project_id}")
        link_id = gns3.find_capture_link(project_id)
        print(f"  Capture link found: {link_id}")
        # NOTE: GNS3 REST API start_capture is unreliable after prior stop_capture calls.
        # User must manually start capture via GNS3 UI before running this script.
        print("  ASSUMING capture was manually started in GNS3 UI on SmartCamera link.")
        print("  (If not, traffic will not be captured. Right-click SmartCamera cable → Start capture)")
    except RuntimeError as exc:
        print(f"  ERROR: {exc}")
        return

    # ------------------------------------------------------------------ #
    # 2. Automated benign traffic generation via Kali SSH
    # ------------------------------------------------------------------ #
    print("=" * 60)
    print(" BENIGN TRAFFIC GENERATION — AUTOMATED (Kali SSH)")
    print("=" * 60)
    print(" SSH to Kali and generate low-rate UDP across 3 IoT targets")
    print(" with varying destination ports. Each port becomes a unique")
    print(" flow in pcap_to_features.py.")
    print(" Expected: ~120 flows in ~10 seconds.")
    print("=" * 60)

    time.sleep(2)
    if not generate_benign_traffic_from_kali():
        print("ERROR: Kali traffic generation failed. Aborting.")
        return
    print("  Waiting 5s for traffic to settle...")
    time.sleep(5)

    # ------------------------------------------------------------------ #
    # 4. Stop capture and retrieve PCAP
    # ------------------------------------------------------------------ #
    print("\nStopping GNS3 capture...")
    try:
        gns3.stop_capture(project_id, link_id)
        time.sleep(2)  # Allow GNS3 to flush and close the file
        pcap_path = gns3.get_latest_pcap()
    except Exception as exc:
        print(f"  ERROR stopping capture or locating PCAP: {exc}")
        return

    if not pcap_path:
        print("  ERROR: GNS3 capture produced no PCAP file. Aborting.")
        return
    print(f"  PCAP located: {pcap_path}")

    # Packet count diagnostic
    try:
        import scapy.all as _scapy
        pkt_count = len(_scapy.rdpcap(pcap_path))
        print(f"  Packets in capture: {pkt_count}")
    except Exception as exc:
        print(f"  WARNING: Could not count packets: {exc}")

    # ------------------------------------------------------------------ #
    # 5. Feature extraction and subnet filtering
    # ------------------------------------------------------------------ #
    print("\nExtracting flow features from PCAP...")
    try:
        all_flows = extract_features_from_pcap(pcap_path)
    except Exception as exc:
        print(f"  ERROR extracting features: {exc}")
        return

    print(f"  Total flows extracted: {len(all_flows)}")

    # Kali is our traffic generator here — its subnet IS valid benign baseline.
    # No filtering needed. Keep all flows.
    filtered_flows = list(all_flows)
    print(f"  Flows accepted as benign baseline: {len(filtered_flows)}")

    if len(filtered_flows) < 50:
        print(
            f"  ERROR: Only {len(filtered_flows)} flows — need at least 50 for "
            "reliable calibration. Generate more benign traffic and retry."
        )
        return

    # ------------------------------------------------------------------ #
    # 6. Load Kitsune model
    # ------------------------------------------------------------------ #
    print(f"\nLoading Kitsune model from: {MODEL_PATH_ABS}")
    if not MODEL_PATH_ABS.exists():
        print(f"  ERROR: Model file not found at {MODEL_PATH_ABS}")
        return

    try:
        with open(MODEL_PATH_ABS, "rb") as f:
            model_data = pickle.load(f)
    except Exception as exc:
        print(f"  ERROR loading model pkl: {exc}")
        return

    kitsune = model_data["kitsune"]
    norm_params = model_data["norm_params"]
    old_threshold = model_data.get("threshold", 0.02)
    print(f"  Model loaded. Current threshold: {old_threshold}")

    # ------------------------------------------------------------------ #
    # 7. Run benign flows through Kitsune and collect RMSE
    # ------------------------------------------------------------------ #
    print("\nRunning benign flows through Kitsune...")
    rmse_list = []
    skipped = 0

    from app.services.pcap_to_features import FEATURE_NAMES as FULL_FEATURE_NAMES
    expected_features = model_data.get("feature_columns", [])
    try:
        feature_indices = [FULL_FEATURE_NAMES.index(name) for name in expected_features]
    except ValueError as missing:
        print(f"ERROR: Feature '{missing}' expected by model is not in pcap_to_features output")
        return
    print(f"  Projecting 52→{len(feature_indices)} features using model's feature_columns")

    for flow in filtered_flows:
        raw_features = np.array(flow["features"], dtype=np.float64)
        if len(raw_features) != 52:
            skipped += 1
            continue

        features = raw_features[feature_indices]
        min_vals = norm_params["min"]
        range_vals = norm_params["range"]

        if min_vals.shape[0] == features.shape[0]:
            normalized = (features - min_vals) / (range_vals + 1e-10)
            normalized = np.clip(normalized, 0.0, 1.0)
        else:
            normalized = np.clip(features, 0.0, 1.0)

        try:
            rmse = float(kitsune.process(normalized))
            rmse_list.append(rmse)
        except Exception:
            skipped += 1

    print(f"  RMSE collected: {len(rmse_list)}  |  Skipped: {skipped}")

    # ------------------------------------------------------------------ #
    # 8. Compute new threshold from stable non-zero RMSE values
    # ------------------------------------------------------------------ #
    rmse_array = np.array(rmse_list)
    nonzero = rmse_array[rmse_array > 0]

    if nonzero.size < 30:
        print(
            f"  ERROR: Only {nonzero.size} non-zero RMSE samples (need >= 30). "
            "Cannot calibrate. Aborting."
        )
        return

    # Skip first 10% as warmup (Kitsune's initial adaptation period)
    skip = max(1, int(nonzero.size * 0.1))
    stable = nonzero[skip:]

    new_threshold = float(stable.mean() + 3.0 * stable.std())

    # ------------------------------------------------------------------ #
    # 9. Sanity checks
    # ------------------------------------------------------------------ #
    if not np.isfinite(new_threshold) or new_threshold <= 0 or new_threshold > 1.0:
        print(
            f"  ERROR: Computed threshold {new_threshold:.6f} is outside sane range "
            "(0, 1.0]. Aborting — pkl will NOT be overwritten."
        )
        return

    # ------------------------------------------------------------------ #
    # 10. Print comparison
    # ------------------------------------------------------------------ #
    ratio = new_threshold / old_threshold if old_threshold else float("inf")
    print("\n" + "-" * 60)
    print(f"  OLD threshold:    {old_threshold:.8f}")
    print(f"  NEW threshold:    {new_threshold:.8f}")
    print(f"  Ratio NEW/OLD:    {ratio:.3f}x")
    print(f"  Benign RMSE mean: {stable.mean():.8f}")
    print(f"  Benign RMSE std:  {stable.std():.8f}")
    print(f"  Benign RMSE min:  {stable.min():.8f}")
    print(f"  Benign RMSE max:  {stable.max():.8f}")
    print(f"  Stable samples:   {stable.size}  (skipped {skip} warmup)")
    print("-" * 60)

    # ------------------------------------------------------------------ #
    # 11. Backup existing pkl
    # ------------------------------------------------------------------ #
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = str(MODEL_PATH_ABS).replace(".pkl", f".backup_{ts}.pkl")
    try:
        shutil.copy2(MODEL_PATH_ABS, backup_path)
        print(f"\nBackup saved to: {backup_path}")
    except Exception as exc:
        print(f"  ERROR creating backup: {exc}. Aborting — pkl NOT overwritten.")
        return

    # ------------------------------------------------------------------ #
    # 12. Update threshold field in pkl and save
    # ------------------------------------------------------------------ #
    model_data["threshold"] = new_threshold
    model_data["calibration_meta"] = {
        "calibrated_at": datetime.now().isoformat(),
        "old_threshold": old_threshold,
        "new_threshold": new_threshold,
        "benign_flow_count": int(nonzero.size),
        "benign_rmse_mean": float(stable.mean()),
        "benign_rmse_std": float(stable.std()),
        "method": "mu_plus_3_sigma_on_live_benign_iot_traffic",
        "source_pcap": str(pcap_path),
    }

    try:
        with open(MODEL_PATH_ABS, "wb") as f:
            pickle.dump(model_data, f)
        print("Model pkl updated with new threshold.")
    except Exception as exc:
        print(f"  ERROR writing updated pkl: {exc}")
        print(f"  Restore from backup: {backup_path}")
        return

    # ------------------------------------------------------------------ #
    # 13. Save JSON calibration report
    # ------------------------------------------------------------------ #
    report_path = _ROOT / "models" / f"calibration_report_{ts}.json"
    try:
        with open(report_path, "w") as f:
            json.dump(
                {
                    "timestamp": datetime.now().isoformat(),
                    "old_threshold": old_threshold,
                    "new_threshold": new_threshold,
                    "benign_flow_count": int(nonzero.size),
                    "benign_rmse_mean": float(stable.mean()),
                    "benign_rmse_std": float(stable.std()),
                    "benign_rmse_min": float(stable.min()),
                    "benign_rmse_max": float(stable.max()),
                    "source_pcap": str(pcap_path),
                    "backup_pkl": backup_path,
                },
                f,
                indent=2,
            )
        print(f"Calibration report saved to: {report_path}")
    except Exception as exc:
        print(f"  WARNING: Could not save JSON report: {exc}")

    print("\n" + "=" * 60)
    print("CALIBRATION COMPLETE")
    print("=" * 60)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Recalibrate Kitsune detection threshold on live benign IoT traffic"
    )
    parser.add_argument(
        "--capture-duration",
        type=int,
        default=90,
        help="Seconds to capture benign traffic (default: 90). "
             "Increase if you need more VPCS ping commands to finish.",
    )
    args = parser.parse_args()

    try:
        calibrate(capture_duration=args.capture_duration)
    except Exception as exc:
        print(f"\nFATAL ERROR: {type(exc).__name__}: {exc}")
        print("pkl has NOT been modified.")
        sys.exit(1)
