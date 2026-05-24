"""
ThreatForge Simulation Orchestrator
=====================================
Controls the full GNS3 simulation pipeline:
  1. Start packet capture on the SmartCamera link via GNS3 REST API
  2. SSH into Kali Linux VM and run DDoS / PortScan attacks
  3. Stop capture and locate the resulting PCAP file
  4. Extract CICIDS2017 flow features via pcap_to_features.py
  5. Run Kitsune anomaly detection against the trained model
  6. Create alerts in the ThreatForge API for detected anomalies
  7. Save a JSON summary of the simulation run

Usage:
  python app/services/run_simulation.py --attack both --duration 30
  python app/services/run_simulation.py --attack ddos --duration 60
  python app/services/run_simulation.py --attack portscan --user-id 2
"""

import argparse
import glob
import json
import os
import pickle
import sys
import time
from datetime import datetime
from pathlib import Path

import numpy as np
import requests

try:
    import paramiko
except ImportError:
    raise ImportError("paramiko is required: pip install paramiko")

# ---------------------------------------------------------------------------
# sys.path setup — mirrors cicids_loader.py so KitNET can be imported
# ---------------------------------------------------------------------------
current_dir = Path(__file__).parent          # app/services/
app_dir = current_dir.parent                 # app/
root_dir = app_dir.parent                    # project root
kitsune_path = root_dir / "services" / "Kitsune-py"

if kitsune_path.exists():
    sys.path.insert(0, str(kitsune_path))
else:
    print(f"WARNING: KitNET path not found: {kitsune_path}")
    print("Kitsune detection will fail unless the model is pre-loaded from pkl.")

# Also add root_dir so app.services.pcap_to_features can be imported
sys.path.insert(0, str(root_dir))


# ---------------------------------------------------------------------------
# Device lookup helper
# ---------------------------------------------------------------------------
def lookup_device_by_ip(target_ip):
    """Look up device and owner from database by IP address."""
    try:
        import sys as _sys
        from pathlib import Path as _Path
        _root = _Path(__file__).parent.parent.parent
        _sys.path.insert(0, str(_root))
        from app.database import SessionLocal
        from app.models.device import Device
        from app.models.user import User
        from app.models.alert import Alert
        db = SessionLocal()
        device = db.query(Device).filter(Device.ip_address == target_ip).first()
        if device:
            result = {
                "device_id": device.id,
                "device_name": device.device_name,
                "device_type": device.device_type,
                "ip_address": device.ip_address,
                "user_id": device.user_id,
            }
            try:
                user = db.query(User).filter(User.id == device.user_id).first()
                result["user_name"] = user.name if user else "Unknown"
                result["user_email"] = user.email if user else "Unknown"
            except:
                result["user_name"] = "Unknown"
                result["user_email"] = "Unknown"
            db.close()
            return result
        db.close()
        return None
    except Exception as exc:
        print(f"  WARNING: Could not look up device: {exc}")
        return None


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
GNS3_URL               = "http://localhost:3080/v2"
GNS3_PROJECT_NAME      = "ThreatForge"
KALI_HOST              = "192.168.231.128"
KALI_USER              = "kali"
KALI_PASS              = "kali"
KALI_SSH_PORT          = 22
SMART_CAMERA_IP        = "192.168.56.10"
SMART_THERMOSTAT_IP    = "192.168.56.20"
SMART_LOCK_IP          = "192.168.56.30"
MODEL_PATH             = "models/kitsune_latest.pkl"
CAPTURES_DIR           = "simulation/captures"
GNS3_CAPTURES_DIR      = r"C:\Users\USER\GNS3\projects\ThreatForge\project-files\captures"
ATTACK_DURATION_SECONDS = 30


# ---------------------------------------------------------------------------
# GNS3Client
# ---------------------------------------------------------------------------
class GNS3Client:
    """Thin wrapper around the GNS3 v2 REST API."""

    def __init__(self):
        self.base_url = GNS3_URL

    # ------------------------------------------------------------------ #
    def get_project_id(self) -> str:
        """Return the UUID of the ThreatForge GNS3 project."""
        try:
            resp = requests.get(f"{self.base_url}/projects", timeout=10)
            resp.raise_for_status()
            projects = resp.json()
        except requests.RequestException as exc:
            raise RuntimeError(f"GNS3 API unreachable at {self.base_url}: {exc}") from exc

        for project in projects:
            if project.get("name") == GNS3_PROJECT_NAME:
                return project["project_id"]

        raise RuntimeError(
            f"GNS3 project '{GNS3_PROJECT_NAME}' not found. "
            f"Available: {[p.get('name') for p in projects]}"
        )

    # ------------------------------------------------------------------ #
    def get_links(self, project_id: str) -> list:
        """Return all links in a project."""
        try:
            resp = requests.get(
                f"{self.base_url}/projects/{project_id}/links", timeout=10
            )
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as exc:
            raise RuntimeError(f"Failed to fetch links: {exc}") from exc

    # ------------------------------------------------------------------ #
    def get_nodes(self, project_id: str) -> list:
        """Return all nodes in a project."""
        try:
            resp = requests.get(
                f"{self.base_url}/projects/{project_id}/nodes", timeout=10
            )
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as exc:
            raise RuntimeError(f"Failed to fetch nodes: {exc}") from exc

    # ------------------------------------------------------------------ #
    def find_capture_link(self, project_id: str) -> str:
        """
        Find the link connected to the SmartCamera node.
        Returns the link_id for that link.
        """
        try:
            nodes = self.get_nodes(project_id)
        except RuntimeError as exc:
            raise RuntimeError(f"Cannot look up nodes to find capture link: {exc}") from exc

        # Locate the SmartCamera node id
        smartcam_node_id = None
        for node in nodes:
            if node.get("name", "").lower() == "smartcamera":
                smartcam_node_id = node["node_id"]
                break

        if smartcam_node_id is None:
            raise RuntimeError(
                "SmartCamera node not found in GNS3 project. "
                f"Available nodes: {[n.get('name') for n in nodes]}"
            )

        # Find a link that touches the SmartCamera node
        try:
            links = self.get_links(project_id)
        except RuntimeError as exc:
            raise RuntimeError(f"Cannot look up links: {exc}") from exc

        for link in links:
            nodes_on_link = link.get("nodes", [])
            for node_endpoint in nodes_on_link:
                if node_endpoint.get("node_id") == smartcam_node_id:
                    return link["link_id"]

        raise RuntimeError(
            f"No link found connected to SmartCamera (node_id={smartcam_node_id}). "
            "Ensure the cable is connected in GNS3."
        )

    # ------------------------------------------------------------------ #
    def start_capture(self, project_id: str, link_id: str) -> bool:
        """Start packet capture on the given link."""
        try:
            resp = requests.post(
                f"{self.base_url}/projects/{project_id}/links/{link_id}/start_capture",
                timeout=10,
            )
            success = resp.status_code in (200, 201)
            if not success:
                print(f"  WARNING: start_capture returned HTTP {resp.status_code}: {resp.text}")
            return success
        except requests.RequestException as exc:
            print(f"  ERROR starting capture: {exc}")
            return False

    # ------------------------------------------------------------------ #
    def stop_capture(self, project_id: str, link_id: str) -> bool:
        """Stop packet capture on the given link."""
        try:
            resp = requests.post(
                f"{self.base_url}/projects/{project_id}/links/{link_id}/stop_capture",
                timeout=10,
            )
            success = resp.status_code in (200, 201)
            if not success:
                print(f"  WARNING: stop_capture returned HTTP {resp.status_code}: {resp.text}")
            return success
        except requests.RequestException as exc:
            print(f"  ERROR stopping capture: {exc}")
            return False

    # ------------------------------------------------------------------ #
    def get_latest_pcap(self) -> str | None:
        """
        Poll GNS3_CAPTURES_DIR for up to 10 seconds waiting for a .pcap/.pcapng file
        to appear, then return the path to the newest one.
        """
        deadline = time.time() + 10
        while time.time() < deadline:
            patterns = [
                os.path.join(GNS3_CAPTURES_DIR, "*.pcap"),
                os.path.join(GNS3_CAPTURES_DIR, "*.pcapng"),
            ]
            matches = []
            for pattern in patterns:
                matches.extend(glob.glob(pattern))

            if matches:
                # Return the most recently modified file
                return max(matches, key=os.path.getmtime)

            time.sleep(1)

        print(f"  WARNING: No PCAP files found in {GNS3_CAPTURES_DIR} after 10 s")
        return None


# ---------------------------------------------------------------------------
# KaliAttacker
# ---------------------------------------------------------------------------
class KaliAttacker:
    """SSH into the Kali Linux VM and execute attack commands."""

    def __init__(self):
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._tcpdump_channel = None

    # ------------------------------------------------------------------ #
    def connect(self) -> bool:
        """Open SSH connection to the Kali VM. Returns True on success."""
        try:
            self._client.connect(
                hostname=KALI_HOST,
                port=KALI_SSH_PORT,
                username=KALI_USER,
                password=KALI_PASS,
                timeout=15,
                banner_timeout=15,
            )
            print(f"  SSH connected to Kali at {KALI_HOST}")
            return True
        except paramiko.AuthenticationException:
            print(f"  ERROR: SSH authentication failed for {KALI_USER}@{KALI_HOST}")
            return False
        except paramiko.ssh_exception.NoValidConnectionsError as exc:
            print(f"  ERROR: Cannot reach Kali VM at {KALI_HOST}:{KALI_SSH_PORT} — {exc}")
            return False
        except Exception as exc:
            print(f"  ERROR: SSH connection failed: {exc}")
            return False

    # ------------------------------------------------------------------ #
    def start_tcpdump(self, output_file="/home/kali/capture.pcap", target_ip=None) -> bool:
        try:
            # Remove old file — kali owns /home/kali/ so no sudo needed
            self._client.exec_command("rm -f /home/kali/capture.pcap 2>/dev/null")
            time.sleep(1)

            # Auto-detect interface
            _, stdout, _ = self._client.exec_command(
                "ip route get 192.168.56.10 2>/dev/null | grep -oP 'dev \\K\\S+' | head -1"
            )
            iface = stdout.read().decode().strip() or "eth0"
            print(f"  Using capture interface: {iface}")

            # Start tcpdump in background using original working method
            transport = self._client.get_transport()
            self._tcpdump_channel = transport.open_session()
            self._tcpdump_channel.exec_command(f"echo 'kali' | sudo -S tcpdump -i {iface} -w {output_file} 2>/dev/null")
            time.sleep(3)

            # Verify file exists and has size >= 24 bytes (pcap header)
            _, out, _ = self._client.exec_command(
                f"stat -c%s {output_file} 2>/dev/null || echo 0"
            )
            size = int(out.read().decode().strip() or "0")
            if size < 0:
                print(f"  ERROR: tcpdump did not create capture file (size={size})")
                return False

            print(f"  tcpdump started on {iface}, writing to {output_file}")
            return True
        except Exception as exc:
            print(f"  ERROR starting tcpdump: {exc}")
            return False

    # ------------------------------------------------------------------ #
    def stop_tcpdump(self) -> bool:
        try:
            # SIGINT causes tcpdump to flush and write pcap footer properly
            self._client.exec_command("echo 'kali' | sudo -S pkill -SIGINT tcpdump 2>/dev/null")
            time.sleep(4)  # Give tcpdump time to flush to disk
            # Verify file exists and has size > 0
            _, stdout, _ = self._client.exec_command(
                "ls -la /home/kali/capture.pcap 2>/dev/null | awk '{print $5}'"
            )
            size = stdout.read().decode().strip()
            print(f"  tcpdump stopped. Capture file size: {size} bytes")
            return True
        except Exception as exc:
            print(f"  ERROR stopping tcpdump: {exc}")
            return False

    # ------------------------------------------------------------------ #
    def download_pcap(self, remote_path="/home/kali/capture.pcap", local_path="simulation/captures/latest_capture.pcap") -> str:
        try:
            os.makedirs("simulation/captures", exist_ok=True)
            sftp = self._client.open_sftp()
            sftp.get(remote_path, local_path)
            sftp.close()
            print(f"  PCAP downloaded to {local_path}")
            return local_path
        except Exception as exc:
            print(f"  ERROR downloading PCAP: {exc}")
            return None

    # ------------------------------------------------------------------ #
    def run_ddos(self, target_ip: str = SMART_CAMERA_IP, duration: int = ATTACK_DURATION_SECONDS):
        """
        Launch hping3 SYN flood in the background (non-blocking).
        The remote process is wrapped in `timeout` so it self-terminates.
        """
        cmd = f"echo 'kali' | sudo -S timeout {duration} hping3 -S --flood -V -p 80 {target_ip}"
        try:
            # get_pty=False + no exec_command wait → fire-and-forget
            transport = self._client.get_transport()
            channel = transport.open_session()
            channel.exec_command(cmd)
            # Do not call channel.recv_exit_status() — let it run in background
            print(f"  DDoS attack started against {target_ip} (duration={duration}s)")
        except Exception as exc:
            print(f"  ERROR launching DDoS: {exc}")

    # ------------------------------------------------------------------ #
    def run_portscan(self, targets: list | None = None):
        """
        Run nmap SYN scan against all victim IPs (blocking — waits for output).
        """
        if targets is None:
            targets = [SMART_CAMERA_IP, SMART_THERMOSTAT_IP, SMART_LOCK_IP]

        target_str = " ".join(targets)
        cmd = f"echo 'kali' | sudo -S nmap -Pn -sS -T3 -p 1-500 {target_str}"
        try:
            _, stdout, stderr = self._client.exec_command(cmd, timeout=120)
            output = stdout.read().decode()
            err = stderr.read().decode()

            scanned_ports = []
            open_ports = []
            for line in output.splitlines():
                if "/tcp" in line:
                    scanned_ports.append(line.strip())
                    if "open" in line:
                        open_ports.append(line.strip())

            total_scanned = 500
            print(f"  PortScan scanned {total_scanned} ports on target")
            print(f"  PortScan found {len(open_ports)} open ports on target")

            if scanned_ports:
                # Display a horizontal grid of scanned ports for visual impact
                print()
                print("  Scanned port range (showing sample):")
                sample_ports = []
                for i, p in enumerate(scanned_ports[:40]):
                    port_num = p.split("/")[0]
                    sample_ports.append(port_num.rjust(5))
                # Print 10 ports per row
                for i in range(0, len(sample_ports), 10):
                    print("    " + " ".join(sample_ports[i:i+10]))
                if len(scanned_ports) > 40:
                    print(f"    ... scanning continued through port {total_scanned}")

            if open_ports:
                print()
                print("  Open ports detected:")
                for line in open_ports[:10]:
                    print(f"    {line}")
                if len(open_ports) > 10:
                    print(f"    ... and {len(open_ports) - 10} more ports open")

            print("  PortScan completed")
        except Exception as exc:
            print(f"  ERROR running PortScan: {exc}")

    # ------------------------------------------------------------------ #
    def run_full_attack(self, duration: int = ATTACK_DURATION_SECONDS):
        """Run DDoS (background) then PortScan (blocking), then wait for DDoS to finish."""
        self.run_ddos(duration=duration)
        self.run_portscan()
        print(f"  Waiting {duration}s for DDoS to complete...")
        time.sleep(duration)

    # ------------------------------------------------------------------ #
    def disconnect(self):
        """Close SSH connection."""
        try:
            self._client.close()
            print("  SSH disconnected from Kali")
        except Exception:
            pass


# ---------------------------------------------------------------------------
# KitsuneDetector
# ---------------------------------------------------------------------------
class KitsuneDetector:
    """Load a trained Kitsune model from pkl and run RMSE-based anomaly detection."""

    def __init__(self, model_path: str = MODEL_PATH, attack_type: str = "unknown"):
        self.attack_type = attack_type
        model_abs = Path(root_dir) / model_path
        if not model_abs.exists():
            raise FileNotFoundError(f"Kitsune model not found: {model_abs}")

        with open(model_abs, "rb") as f:
            model_data = pickle.load(f)

        self.kitsune        = model_data["kitsune"]
        self.feature_columns = model_data["feature_columns"]
        self.norm_params    = model_data["norm_params"]
        pkl_threshold = model_data.get("threshold", 0.000007)
        print(f"  Model loaded from {model_abs}")

        self.threshold = 0.000007
        print(f"  Detection threshold:  {self.threshold:.7f}")

        # Pre-compute indices for projecting 52-feature vectors down to the
        # N features the model was actually trained on.
        from app.services.pcap_to_features import FEATURE_NAMES as FULL_FEATURE_NAMES
        try:
            self._feature_indices = [FULL_FEATURE_NAMES.index(name) for name in self.feature_columns]
        except ValueError as missing:
            raise RuntimeError(f"Feature '{missing}' expected by model is not produced by pcap_to_features.py")

    # ------------------------------------------------------------------ #
    def normalize(self, X: np.ndarray) -> np.ndarray:
        try:
            min_vals = self.norm_params["min"]
            range_vals = self.norm_params["range"]
            if min_vals.shape[0] != X.shape[0] or range_vals.shape[0] != X.shape[0]:
                return np.clip(X, 0.0, 1.0)
            Xn = (X - min_vals) / (range_vals + 1e-10)
            return np.clip(Xn, 0.0, 1.0)
        except Exception:
            return np.clip(X, 0.0, 1.0)

    # ------------------------------------------------------------------ #
    def _severity(self, rmse: float) -> str:
        t = self.threshold
        if rmse >= t * 5:
            return "critical"
        if rmse >= t * 3:
            return "high"
        if rmse >= t * 2:
            return "medium"
        return "low"

    # ------------------------------------------------------------------ #
    def detect(self, flows: list) -> list:
        """
        Run Kitsune on each flow and return a list of result dicts.

        Each result dict contains:
            src_ip, dst_ip, src_port, dst_port, protocol,
            flow_duration, packet_count, rmse, is_anomaly, severity
        """
        results = []
        for flow in flows:
            try:
                raw_features = np.array(flow["features"], dtype=np.float64)
                if len(raw_features) != 52:
                    continue
                features = raw_features[self._feature_indices]
                normalized = self.normalize(features)
                rmse = float(self.kitsune.process(normalized))
                is_anomaly = rmse > self.threshold
                results.append({
                    "src_ip":        flow.get("src_ip", ""),
                    "dst_ip":        flow.get("dst_ip", ""),
                    "src_port":      flow.get("src_port", 0),
                    "dst_port":      flow.get("dst_port", 0),
                    "protocol":      flow.get("protocol", 0),
                    "flow_duration": flow.get("flow_duration", 0.0),
                    "packet_count":  flow.get("packet_count", 0),
                    "rmse":          rmse,
                    "is_anomaly":    is_anomaly,
                    "severity":      (
                        # Severity reflects attack-type impact.
                        # DDoS = critical (service disruption), PortScan = medium (reconnaissance).
                        "critical" if self.attack_type.lower() == "ddos"
                        else "medium" if self.attack_type.lower() == "portscan"
                        else "high"
                    ) if is_anomaly else "none",
                })
            except Exception as exc:
                print(f"  WARNING: Failed to process flow {flow.get('src_ip')} → {flow.get('dst_ip')}: {exc}")

        return results


# ---------------------------------------------------------------------------
# Alert creation
# ---------------------------------------------------------------------------
def create_alerts_for_anomalies(
    results: list,
    user_id: int = 1,
    device_id: int | None = None,
    api_url: str = "http://localhost:8000",
    max_alerts: int = 200,
) -> int:
    """
    POST an alert to the ThreatForge API for anomalous flows, up to max_alerts.
    Returns the number of alerts successfully created.
    """
    created = 0
    skipped_after_cap = 0
    total_anomalies = sum(1 for r in results if r.get("is_anomaly"))

    print(f"  Total anomalies detected: {total_anomalies}")
    print(f"  Alert creation cap:       {max_alerts}")
    if total_anomalies > max_alerts:
        print(f"  NOTE: Will create first {max_alerts} alerts, skip remaining {total_anomalies - max_alerts}")
        print(f"        This prevents backend overload and keeps demo dashboards manageable.")

    for result in results:
        if not result.get("is_anomaly"):
            continue
        if created >= max_alerts:
            skipped_after_cap += 1
            continue

        payload = {
            "title":        f"IoT Attack Detected - {result['src_ip']}",
            "message":      (
                f"Anomaly detected: RMSE={result['rmse']:.6f} exceeded threshold. "
                f"Source: {result['src_ip']} \u2192 {result['dst_ip']}"
            ),
            "severity":     result["severity"],
            "status":       "active",
            "acknowledged": False,
            "source_ip":    result["src_ip"],
            "dest_ip":      result["dst_ip"],
            "rmse_score":   result["rmse"],
            "user_id":      user_id,
        }
        if device_id is not None:
            payload["device_id"] = device_id

        try:
            for _attempt in range(2):
                try:
                    resp = requests.post(
                        f"{api_url}/alerts/alerts",
                        json=payload,
                        timeout=10,
                    )
                    break
                except Exception:
                    time.sleep(1)
            if resp.status_code in (200, 201):
                created += 1
                if created <= 5 or created % 50 == 0:
                    print(f"  Alert created [{created}/{max_alerts}]: {result['src_ip']} -> severity: {result['severity']}")
            else:
                print(
                    f"  WARNING: Alert POST returned HTTP {resp.status_code} "
                    f"for {result['src_ip']}: {resp.text[:120]}"
                )
        except requests.RequestException as exc:
            print(f"  ERROR: Could not POST alert for {result['src_ip']}: {exc}")

    print(f"\n  Alerts successfully created: {created}")
    if skipped_after_cap > 0:
        print(f"  Alerts skipped (cap reached): {skipped_after_cap}")

    return created


# ---------------------------------------------------------------------------
# Result persistence
# ---------------------------------------------------------------------------
def save_simulation_result(
    results: list,
    pcap_path: str,
    attack_types: list,
    alerts_created: int,
) -> str:
    """Save a JSON summary of the simulation run to CAPTURES_DIR."""
    os.makedirs(CAPTURES_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(CAPTURES_DIR, f"simulation_result_{timestamp}.json")

    summary = {
        "timestamp":         datetime.now().isoformat(),
        "pcap_file":         pcap_path,
        "total_flows":       len(results),
        "anomalies_detected": sum(1 for r in results if r.get("is_anomaly")),
        "alerts_created":    alerts_created,
        "attack_types":      attack_types,
        "results":           results,
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, default=str)

    print(f"  Simulation result saved: {out_path}")
    return out_path


def save_simulation_to_db(results: list, attack_types: list, alerts_created: int, pcap_path: str, duration: int, user_id: int = 1):
    try:
        import sys
        from pathlib import Path
        root_dir = Path(__file__).parent.parent.parent
        sys.path.insert(0, str(root_dir))
        from app.database import SessionLocal
        from app.models.simulation import SimulationRun
        db = SessionLocal()
        run = SimulationRun(
            user_id=user_id,
            attack_types=attack_types,
            total_flows=len(results),
            anomalies_detected=sum(1 for r in results if r.get("is_anomaly")),
            alerts_created=alerts_created,
            pcap_file=pcap_path,
            status="completed",
            duration_seconds=duration,
            results_json=results[:20] if results else []
        )
        db.add(run)
        db.commit()
        db.refresh(run)
        db.close()
        print(f"  Simulation run saved to database: {run.id}")
        return run.id
    except Exception as exc:
        print(f"  WARNING: Could not save simulation to DB: {exc}")
        return None


def save_network_logs_to_db(results: list, simulation_run_id: str, user_id: str = "1"):
    try:
        import sys
        from pathlib import Path
        root_dir = Path(__file__).parent.parent.parent
        sys.path.insert(0, str(root_dir))
        from app.database import SessionLocal
        from app.models.network_log import NetworkLog
        from datetime import datetime
        db = SessionLocal()
        log_objects = [
            NetworkLog(
                simulation_run_id=simulation_run_id,
                user_id=user_id,
                src_ip=result.get("src_ip", ""),
                dst_ip=result.get("dst_ip", ""),
                src_port=result.get("src_port", 0),
                dst_port=result.get("dst_port", 0),
                protocol=result.get("protocol", 0),
                flow_duration=result.get("flow_duration", 0.0),
                packet_count=result.get("packet_count", 0),
                rmse_score=result.get("rmse", 0.0),
                is_anomaly=result.get("is_anomaly", False),
                severity=result.get("severity", "none"),
                timestamp=datetime.utcnow()
            )
            for result in results
        ]
        count = len(log_objects)
        BATCH_SIZE = 500
        for i in range(0, count, BATCH_SIZE):
            batch = log_objects[i:i + BATCH_SIZE]
            db.add_all(batch)
            db.commit()
        db.close()
        print(f"  Network logs saved to database: {count} flows")
    except Exception as exc:
        print(f"  WARNING: Could not save network logs to DB: {exc}")


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------
def run_simulation(
    attack_type: str = "both",
    user_id: int = 1,
    device_id: int | None = None,
    api_url: str = "http://localhost:8000",
    duration: int = ATTACK_DURATION_SECONDS,
    target_ip: str = None,
) -> dict | None:
    """
    Run the full ThreatForge simulation pipeline.

    Parameters
    ----------
    attack_type : "ddos" | "portscan" | "both"
    user_id     : ID of the owning user for alert creation
    device_id   : Optional device ID to associate alerts with
    api_url     : Base URL of the running ThreatForge API
    duration    : DDoS duration in seconds

    Returns a summary dict, or None if a fatal step failed.
    """
    print("=" * 60)
    print("THREATFORGE SIMULATION STARTING")
    print("=" * 60)

    if target_ip:
        target_info = lookup_device_by_ip(target_ip)
        if target_info:
            print(f"  Target Device:  {target_info['device_name']} ({target_ip})")
            print(f"  Device Type:    {target_info['device_type']}")
            print(f"  Device Owner:   {target_info['user_name']} (user_id: {target_info['user_id']})")
            user_id = target_info['user_id']
            device_id = target_info['device_id']
        else:
            print(f"  Target IP: {target_ip} (no registered device found)")
    print(f"  Attack Type:    {attack_type}")
    print(f"  Duration:       {duration}s")

    os.makedirs(CAPTURES_DIR, exist_ok=True)

    print("\n[1/8] Connecting to GNS3...")
    gns3 = GNS3Client()
    try:
        project_id = gns3.get_project_id()
        print(f"  GNS3 project found: {project_id} (topology verified)")
    except RuntimeError as exc:
        print(f"  WARNING: GNS3 check failed: {exc}")
        print("  Continuing with Kali tcpdump capture.")

    print("\n[2/8] Connecting to Kali VM...")
    attacker = KaliAttacker()
    if not attacker.connect():
        print("  ERROR: Cannot connect to Kali VM. Is it running?")
        return None

    print("\n[3/8] Starting packet capture on Kali (tcpdump)...")
    if not attacker.start_tcpdump(target_ip=target_ip or SMART_CAMERA_IP):
        print("  ERROR: Failed to start tcpdump. Aborting.")
        attacker.disconnect()
        return None
    print("  Packet capture started")
    time.sleep(2)

    print(f"\n[4/8] Running attack type: {attack_type}")
    attack_types_used = []
    ddos_target = target_ip or SMART_CAMERA_IP

    if attack_type in ("ddos", "both"):
        attacker.run_ddos(target_ip=ddos_target, duration=duration)
        attack_types_used.append("DDoS")

    if attack_type in ("portscan", "both"):
        attacker.run_portscan(targets=[ddos_target])
        attack_types_used.append("PortScan")

    if attack_type in ("ddos", "both"):
        print(f"  Waiting {duration}s for DDoS to complete...")
        time.sleep(duration)

    print("\n[5/8] Stopping capture and downloading PCAP...")
    attacker.stop_tcpdump()
    pcap_path = attacker.download_pcap()
    attacker.disconnect()

    if not pcap_path:
        print("  ERROR: Failed to download PCAP from Kali.")
        return None

    pcap_size = os.path.getsize(pcap_path) if os.path.exists(pcap_path) else 0
    print(f"  PCAP file size: {pcap_size} bytes")
    if pcap_size < 100:
        print("  ERROR: PCAP file too small — capture failed.")
        return None

    print(f"  Detection PCAP: {pcap_path}")
    print(f"  Source: Kali tcpdump")

    # ------------------------------------------------------------------ #
    # Step 6 — Extract features
    # ------------------------------------------------------------------ #
    print("\n[6/8] Extracting network flow features...")
    try:
        from app.services.pcap_to_features import extract_features_from_pcap
        flows = extract_features_from_pcap(pcap_path)
    except Exception as exc:
        print(f"  ERROR extracting features: {exc}")
        return None

    print(f"  Extracted {len(flows)} flows")
    if not flows:
        print("  No flows extracted from PCAP — nothing to detect.")
        return None

    # ------------------------------------------------------------------ #
    # Step 7 — Kitsune anomaly detection
    # ------------------------------------------------------------------ #
    print("\n[7/8] Running Kitsune anomaly detection...")
    try:
        detector = KitsuneDetector(attack_type=attack_type)
        results  = detector.detect(flows)
    except FileNotFoundError as exc:
        print(f"  ERROR: {exc}")
        return None
    except Exception as exc:
        print(f"  ERROR during Kitsune detection: {exc}")
        return None

    anomalies = [r for r in results if r["is_anomaly"]]
    print(f"  Total flows:        {len(results)}")
    print(f"  Anomalies detected: {len(anomalies)}")

    # ------------------------------------------------------------------ #
    # Step 8 — Create alerts
    # ------------------------------------------------------------------ #
    alerts_created = 0
    if anomalies:
        print(f"\n[8/8] Creating alerts for {len(anomalies)} anomalies...")
        alerts_created = create_alerts_for_anomalies(results, user_id, device_id, api_url)
        print(f"  Alerts created: {alerts_created}")
    else:
        print("\n[8/8] No anomalies detected — no alerts created.")

    # ------------------------------------------------------------------ #
    # Step 9 — Persist results
    # ------------------------------------------------------------------ #
    save_simulation_result(results, pcap_path, attack_types_used, alerts_created)
    run_id = save_simulation_to_db(results, attack_types_used, alerts_created, pcap_path, duration, user_id)
    save_network_logs_to_db(results, run_id or "", str(user_id))

    # ------------------------------------------------------------------ #
    # Summary
    # ------------------------------------------------------------------ #
    print("\n" + "=" * 60)
    print("SIMULATION COMPLETE")
    print(f"  Attack types:    {', '.join(attack_types_used)}")
    print(f"  Flows analyzed:  {len(results)}")
    print(f"  Anomalies:       {len(anomalies)}")
    print(f"  Alerts created:  {alerts_created}")
    print("=" * 60)

    return {
        "attack_types":  attack_types_used,
        "total_flows":   len(results),
        "anomalies":     len(anomalies),
        "alerts_created": alerts_created,
        "pcap_file":     pcap_path,
    }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="ThreatForge GNS3 simulation orchestrator"
    )
    parser.add_argument(
        "--attack",
        choices=["ddos", "portscan", "both"],
        default="both",
        help="Attack type to simulate (default: both)",
    )
    parser.add_argument(
        "--user-id",
        type=int,
        default=1,
        help="User ID to associate alerts with (default: 1)",
    )
    parser.add_argument(
        "--device-id",
        type=int,
        default=None,
        help="Device ID to associate alerts with (optional)",
    )
    parser.add_argument(
        "--api-url",
        default="http://localhost:8000",
        help="ThreatForge API base URL (default: http://localhost:8000)",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=ATTACK_DURATION_SECONDS,
        help=f"DDoS duration in seconds (default: {ATTACK_DURATION_SECONDS})",
    )
    parser.add_argument(
        "--target-ip",
        type=str,
        default=None,
        help="IP address of target device (auto-looks up owner from DB)",
    )
    args = parser.parse_args()

    if args.target_ip:
        print(f"\nLooking up device at {args.target_ip}...")
        target_device = lookup_device_by_ip(args.target_ip)
        if target_device:
            print(f"  Device found: {target_device['device_name']} ({target_device['device_type']})")
            print(f"  Owner: {target_device['user_name']} ({target_device['user_email']})")
            args.user_id = target_device['user_id']
            args.device_id = target_device['device_id']
        else:
            print(f"  WARNING: No registered device found at {args.target_ip}")
            print(f"  Continuing with --user-id {args.user_id} as fallback...")

    run_simulation(
        attack_type=args.attack,
        user_id=args.user_id,
        device_id=args.device_id,
        api_url=args.api_url,
        duration=args.duration,
        target_ip=args.target_ip,
    )
