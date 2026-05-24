"""
Analyze RMSE distribution from the latest simulation result.
Used to design severity bands that produce meaningful gradient
instead of everything bucketing into 'critical'.
"""
import json
from pathlib import Path
import numpy as np

BACKEND_DIR = Path(__file__).parent.parent.parent
CAPTURES_DIR = BACKEND_DIR / "simulation" / "captures"

def main():
    # Find most recent simulation_result_*.json
    result_files = sorted(
        CAPTURES_DIR.glob("simulation_result_*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not result_files:
        print("No simulation_result_*.json files found.")
        return

    latest = result_files[0]
    print(f"Analyzing: {latest.name}")
    print(f"Modified:  {latest.stat().st_mtime}")

    with open(latest, "r") as f:
        data = json.load(f)

    # Structure depends on how run_simulation.py saves it.
    # Try both common layouts.
    results = data.get("results") or data.get("flows") or data.get("detection_results") or []
    if not results:
        # Maybe data IS the results list
        if isinstance(data, list):
            results = data
        else:
            print(f"Unrecognized JSON structure. Keys: {list(data.keys())[:20]}")
            return

    print(f"Total flow records: {len(results)}")

    rmses = [float(r["rmse"]) for r in results if "rmse" in r and r.get("rmse") is not None]
    anomaly_rmses = [float(r["rmse"]) for r in results if r.get("is_anomaly") and "rmse" in r]

    print(f"Records with RMSE: {len(rmses)}")
    print(f"Records flagged as anomaly: {len(anomaly_rmses)}")

    if not rmses:
        print("No RMSE values found in results.")
        return

    all_rmse = np.array(rmses)
    anom_rmse = np.array(anomaly_rmses) if anomaly_rmses else np.array([])

    print("\n" + "="*60)
    print(" OVERALL RMSE DISTRIBUTION (all flows)")
    print("="*60)
    print(f"  Min:     {all_rmse.min():.9f}")
    print(f"  Max:     {all_rmse.max():.9f}")
    print(f"  Mean:    {all_rmse.mean():.9f}")
    print(f"  Median:  {np.median(all_rmse):.9f}")
    print(f"  Std:     {all_rmse.std():.9f}")

    print("\n  Percentiles:")
    for pct in [10, 25, 50, 75, 90, 95, 99]:
        print(f"    p{pct:2d}:  {np.percentile(all_rmse, pct):.9f}")

    if len(anom_rmse) > 0:
        print("\n" + "="*60)
        print(" ANOMALY-ONLY RMSE DISTRIBUTION (flows above threshold)")
        print("="*60)
        print(f"  Min:     {anom_rmse.min():.9f}")
        print(f"  Max:     {anom_rmse.max():.9f}")
        print(f"  Mean:    {anom_rmse.mean():.9f}")
        print(f"  Median:  {np.median(anom_rmse):.9f}")
        print(f"  Std:     {anom_rmse.std():.9f}")

        print("\n  Percentiles (anomalies only):")
        for pct in [10, 25, 50, 75, 90, 95, 99]:
            print(f"    p{pct:2d}:  {np.percentile(anom_rmse, pct):.9f}")

        print("\n" + "="*60)
        print(" RECOMMENDED SEVERITY BANDS (based on anomaly percentiles)")
        print("="*60)
        p25 = np.percentile(anom_rmse, 25)
        p50 = np.percentile(anom_rmse, 50)
        p75 = np.percentile(anom_rmse, 75)
        print(f"  low:      RMSE <  {p25:.9f}  (below 25th percentile)")
        print(f"  medium:   {p25:.9f} <= RMSE < {p50:.9f}  (25-50th)")
        print(f"  high:     {p50:.9f} <= RMSE < {p75:.9f}  (50-75th)")
        print(f"  critical: RMSE >= {p75:.9f}  (above 75th percentile)")

if __name__ == "__main__":
    main()
