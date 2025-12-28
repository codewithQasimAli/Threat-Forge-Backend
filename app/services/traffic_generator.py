import random
import time
from datetime import datetime
import requests
import json

class TrafficGenerator:
    
    def __init__(self, api_url="http://localhost:8000", user_id=1, device_id=None):
        self.api_url = api_url
        self.user_id = user_id
        self.device_id = device_id
        self.normal_ips = [f"192.168.1.{i}" for i in range(10, 50)]
        self.server_ips = ["192.168.1.1", "8.8.8.8", "1.1.1.1", "10.0.0.1"]
        self.suspicious_ips = [f"192.168.1.{i}" for i in range(90, 100)]
        self.common_ports = [80, 443, 22, 3306, 5432, 8080]
        self.successful = 0
        self.failed = 0
        self.anomalies_generated = 0
        self.timeout_errors = 0
        self.connection_errors = 0
        
    def generate_normal_packet(self):
        """Generate a normal network packet with consistent patterns"""
        protocol = random.choice(['TCP', 'UDP'])
        
        packet = {
            'user_id': self.user_id,
            'device_id': self.device_id,
            'timestamp': datetime.now().timestamp(),
            'source_ip': random.choice(self.normal_ips[:10]),
            'dest_ip': random.choice(self.server_ips[:2]),
            'source_port': random.randint(49152, 65535),
            'dest_port': random.choice([80, 443]),
            'protocol': protocol,
            'length': random.randint(500, 1500)
        }
        
        return packet
    
    def generate_anomalous_packet(self):
        """Generate MORE EXTREME anomalous packets"""
        packet = self.generate_normal_packet()
        
        anomaly_type = random.choice([
            'large_packet',
            'tiny_packet',
            'unusual_port',
            'port_scan',
            'suspicious_combo',
            'extreme_values',
            'different_subnet',
            'broadcast_storm',
            'icmp_flood',
            'udp_flood'
        ])
        
        if anomaly_type == 'large_packet':
            packet['length'] = random.randint(8000, 15000)
            packet['dest_port'] = random.choice([8080, 3128])
            packet['protocol'] = 'TCP'
            
        elif anomaly_type == 'tiny_packet':
            packet['length'] = random.randint(1, 50)
            packet['dest_port'] = random.choice([23, 21, 25])
            packet['protocol'] = 'TCP'
            
        elif anomaly_type == 'unusual_port':
            packet['dest_port'] = random.choice([31337, 12345, 54321, 6667, 1337, 4444])
            packet['length'] = random.randint(100, 500)
            packet['protocol'] = 'TCP'
            
        elif anomaly_type == 'port_scan':
            packet['source_ip'] = random.choice(self.suspicious_ips)
            packet['dest_port'] = random.randint(1, 1024)
            packet['length'] = 64
            packet['protocol'] = 'TCP'
            
        elif anomaly_type == 'suspicious_combo':
            packet['dest_port'] = 23
            packet['length'] = random.randint(5000, 8000)
            packet['source_ip'] = random.choice(self.suspicious_ips)
            packet['protocol'] = 'TCP'
            
        elif anomaly_type == 'extreme_values':
            packet['length'] = random.choice([1, 10000, 65535])
            packet['dest_port'] = random.choice([1, 7, 13, 65535])
            packet['source_port'] = random.choice([1, 20, 65535])
            packet['protocol'] = random.choice(['TCP', 'UDP', 'ICMP'])
            
        elif anomaly_type == 'different_subnet':
            packet['source_ip'] = f"10.{random.randint(10, 50)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            packet['dest_port'] = random.choice([445, 139, 135, 3389])
            packet['length'] = random.randint(100, 300)
            packet['protocol'] = 'TCP'
            
        elif anomaly_type == 'broadcast_storm':
            packet['source_ip'] = random.choice(self.normal_ips)
            packet['dest_ip'] = "255.255.255.255"
            packet['dest_port'] = random.choice([67, 68, 137, 138])
            packet['length'] = random.randint(100, 500)
            packet['protocol'] = 'UDP'
            
        elif anomaly_type == 'icmp_flood':
            packet['protocol'] = 'ICMP'
            packet['source_ip'] = random.choice(self.suspicious_ips)
            packet['length'] = random.randint(56, 1500)
            packet['dest_port'] = 0
            packet['source_port'] = 0
            
        elif anomaly_type == 'udp_flood':
            packet['protocol'] = 'UDP'
            packet['source_ip'] = random.choice(self.suspicious_ips)
            packet['dest_port'] = random.randint(1, 65535)
            packet['length'] = random.randint(1, 100)
        
        return packet
    
    def send_packet_batch(self, packets):
        """Send multiple packets in a single request"""
        try:
            # Send each packet individually but without waiting
            success_count = 0
            for packet in packets:
                response = requests.post(
                    f"{self.api_url}/alerts/kitsune/process-packet",
                    json=packet,
                    timeout=5
                )
                if response.status_code in [200, 201]:
                    success_count += 1
            return success_count
        except requests.exceptions.Timeout:
            self.timeout_errors += len(packets)
            return 0
        except requests.exceptions.ConnectionError:
            self.connection_errors += len(packets)
            return 0
        except Exception as e:
            print(f"  [ERROR] {type(e).__name__}: {str(e)[:50]}")
            return 0
    
    def run_simulation(self, total_packets=1000, anomaly_rate=0.05, batch_size=50,
                       show_progress_every=100):
        print(f"\n{'='*60}")
        print(f"TRAFFIC SIMULATION STARTING (BATCH MODE)")
        print(f"{'='*60}")
        print(f"  Total packets: {total_packets}")
        print(f"  User ID: {self.user_id}")
        print(f"  Device ID: {self.device_id}")
        print(f"  Anomaly rate: {anomaly_rate * 100}%")
        print(f"  Batch size: {batch_size} packets")
        print(f"  Estimated batches: {total_packets // batch_size}")
        print(f"  Estimated time: {(total_packets // batch_size) * 2:.1f} seconds")
        print(f"  Target: {self.api_url}")
        print(f"{'='*60}\n")
        
        # Reset stats
        self.successful = 0
        self.failed = 0
        self.anomalies_generated = 0
        self.timeout_errors = 0
        self.connection_errors = 0
        start_time = time.time()
        
        packets_sent = 0
        
        # Send packets in batches
        while packets_sent < total_packets:
            batch = []
            batch_target = min(batch_size, total_packets - packets_sent)
            
            # Generate batch
            for _ in range(batch_target):
                is_anomaly = random.random() < anomaly_rate
                if is_anomaly:
                    packet = self.generate_anomalous_packet()
                    self.anomalies_generated += 1
                else:
                    packet = self.generate_normal_packet()
                batch.append(packet)
            
            # Send batch
            success_count = self.send_packet_batch(batch)
            self.successful += success_count
            self.failed += (batch_target - success_count)
            packets_sent += batch_target
            
            # Show progress after each batch
            elapsed = time.time() - start_time
            packets_per_sec = packets_sent / elapsed if elapsed > 0 else 0
            progress_pct = (packets_sent * 100) // total_packets
            
            # Print simple progress line after each batch
            print(f"[{progress_pct}%] {packets_sent}/{total_packets} packets | "
                  f"Speed: {packets_per_sec:.1f} p/s | "
                  f"Anomalies: {self.anomalies_generated}", 
                  flush=True)
            
            # Detailed progress every show_progress_every packets
            if packets_sent % show_progress_every == 0 or packets_sent == total_packets:
                print(f"\n{'='*60}")
                print(f"PROGRESS UPDATE: {packets_sent}/{total_packets} packets ({progress_pct}%)")
                print(f"{'='*60}")
                print(f"  Success: {self.successful}, Failed: {self.failed}")
                print(f"  Anomalies generated: {self.anomalies_generated}")
                print(f"  Speed: {packets_per_sec:.1f} packets/sec")
                print(f"  Elapsed: {elapsed:.1f}s")
                if self.timeout_errors > 0 or self.connection_errors > 0:
                    print(f"  Errors: {self.timeout_errors} timeouts, {self.connection_errors} connection")
                
                # Get Kitsune statistics
                self._print_kitsune_stats()
                print(f"{'='*60}\n")
        
        # Final summary
        elapsed = time.time() - start_time
        print(f"\n{'='*60}")
        print(f"SIMULATION COMPLETED")
        print(f"{'='*60}")
        print(f"  Total sent: {self.successful}/{total_packets}")
        print(f"  Failed: {self.failed}")
        print(f"  Anomalies generated: {self.anomalies_generated}")
        print(f"  Total time: {elapsed:.1f} seconds")
        print(f"  Average speed: {total_packets/elapsed:.1f} packets/sec")
        if self.timeout_errors > 0 or self.connection_errors > 0:
            print(f"  Total errors: {self.timeout_errors} timeouts, {self.connection_errors} connection")
        print(f"{'='*60}\n")
        
        # Get final alerts
        self._print_alerts()
    
    def _print_kitsune_stats(self):
        """Helper to print Kitsune statistics"""
        try:
            stats_response = requests.get(
                f"{self.api_url}/alerts/kitsune/statistics",
                timeout=5
            )
            if stats_response.status_code == 200:
                stats = stats_response.json()
                phase = stats.get('training_phase', 'unknown')
                progress = stats.get('progress_percentage', 0)
                detected = stats.get('anomalies_detected', 0)
                threshold = stats.get('anomaly_threshold', 0)
                last_rmse = stats.get('last_rmse_score', 0)
                
                print(f"  Kitsune phase: {phase}")
                print(f"  Training progress: {progress:.1f}%")
                print(f"  Anomalies detected: {detected}")
                print(f"  Threshold: {threshold:.8f}")
                print(f"  Last RMSE: {last_rmse:.8f}")
                
                if phase == 'feature_mapping':
                    print(f"  Status: Learning network structure")
                elif phase == 'training':
                    print(f"  Status: Training autoencoders")
                elif phase == 'detection':
                    print(f"  Status: Active detection mode")
        except requests.exceptions.Timeout:
            print(f"  [WARN] Stats request timed out")
        except Exception:
            pass
    
    def _print_alerts(self):
        """Helper to print alerts summary"""
        try:
            alerts_response = requests.get(
                f"{self.api_url}/alerts/alerts/user/{self.user_id}",
                timeout=10
            )
            if alerts_response.status_code == 200:
                alerts = alerts_response.json()
                alert_count = len(alerts)
                print(f"[ALERTS] Total alerts created: {alert_count}")
                
                if alert_count > 0:
                    severities = {}
                    for alert in alerts:
                        sev = alert.get('severity', 'unknown')
                        severities[sev] = severities.get(sev, 0) + 1
                    
                    print(f"\nAlert Severity Breakdown:")
                    for sev, count in severities.items():
                        print(f"  {sev.upper()}: {count}")
                    
                    print(f"\nAnomalies detected successfully!")
                    print(f"\nView all alerts:")
                    print(f"  GET {self.api_url}/alerts/alerts/user/{self.user_id}")
                    
                    # Show last few alerts
                    print(f"\nRecent Alerts (last 5):")
                    for alert in alerts[-5:]:
                        print(f"  - [{alert.get('severity', '?').upper()}] {alert.get('title', 'Unknown')}")
                        print(f"    RMSE: {alert.get('rmse_score', 0):.6f}")
                else:
                    print(f"\nNo alerts created yet.")
                    print(f"  Possible reasons:")
                    print(f"    1. Still in training phase")
                    print(f"    2. Anomalies not extreme enough")
                    print(f"    3. Threshold may need adjustment")
        except requests.exceptions.Timeout:
            print(f"[WARN] Alerts request timed out")
        except Exception as e:
            print(f"Could not fetch alerts: {type(e).__name__}")


def main():
    print("="*60)
    print("KITSUNE IDS - TRAFFIC GENERATOR (OPTIMIZED)")
    print("="*60)
    print()
    
    user_id = input("Enter user_id (default: 1): ").strip() or "1"
    device_id = input("Enter device_id (optional, press Enter to skip): ").strip() or None
    
    if device_id:
        device_id = int(device_id)
    
    generator = TrafficGenerator(
        api_url="http://localhost:8000",
        user_id=int(user_id),
        device_id=device_id
    )
    
    print("\n" + "="*60)
    print("TRAFFIC GENERATOR OPTIONS")
    print("="*60)
    print()
    print("FAST (completes in 30-60 seconds):")
    print("  1. Quick training (2000 packets, ~40 sec)")
    print("  2. Detection test (1000 packets, 30% anomalies, ~20 sec)")
    print("  3. Complete workflow (train + detect, ~60 sec)")
    print()
    print("EXTENDED (Better accuracy, 2-3 minutes):")
    print("  4. Extended training (5000 packets)")
    print("  5. Full workflow (train 5000 + detect 2000)")
    print()
    print("OTHER:")
    print("  6. Custom configuration")
    print("="*60)
    
    choice = input("\nSelect option (1-6): ").strip()
    
    if choice == "1":
        print("\n[QUICK TRAINING MODE]")
        print("Training with 2000 packets (5% anomalies)")
        generator.run_simulation(
            total_packets=2000, 
            anomaly_rate=0.05,
            batch_size=50,
            show_progress_every=400
        )
        print("\n[COMPLETE] Training finished!")
        print("Now run option 2 for detection test.")
        
    elif choice == "2":
        print("\n[DETECTION TEST MODE]")
        print("Sending 1000 packets with 30% anomalies")
        generator.run_simulation(
            total_packets=1000, 
            anomaly_rate=0.30,
            batch_size=50,
            show_progress_every=200
        )
        
    elif choice == "3":
        print("\n[COMPLETE WORKFLOW MODE]")
        print("Running training then detection test")
        print()
        
        # Training phase
        print("=" * 60)
        print("PHASE 1: TRAINING")
        print("=" * 60)
        generator.run_simulation(
            total_packets=2000, 
            anomaly_rate=0.05,
            batch_size=50,
            show_progress_every=400
        )
        
        print("\n" + "=" * 60)
        print("Waiting 2 seconds...")
        print("=" * 60)
        time.sleep(2)
        
        # Detection phase
        print("\n" + "=" * 60)
        print("PHASE 2: DETECTION TEST")
        print("=" * 60)
        generator.run_simulation(
            total_packets=1000, 
            anomaly_rate=0.30,
            batch_size=50,
            show_progress_every=200
        )
        
    elif choice == "4":
        print("\n[EXTENDED TRAINING MODE]")
        print("Training with 5000 packets for better accuracy")
        generator.run_simulation(
            total_packets=5000, 
            anomaly_rate=0.05,
            batch_size=50,
            show_progress_every=500
        )
        
    elif choice == "5":
        print("\n[FULL WORKFLOW MODE]")
        print("Running extended training then detection")
        print()
        
        # Extended training
        print("=" * 60)
        print("PHASE 1: EXTENDED TRAINING")
        print("=" * 60)
        generator.run_simulation(
            total_packets=5000, 
            anomaly_rate=0.05,
            batch_size=50,
            show_progress_every=500
        )
        
        time.sleep(2)
        
        # Detection
        print("\n" + "=" * 60)
        print("PHASE 2: DETECTION TEST")
        print("=" * 60)
        generator.run_simulation(
            total_packets=2000, 
            anomaly_rate=0.30,
            batch_size=50,
            show_progress_every=400
        )
        
    elif choice == "6":
        print("\n[CUSTOM CONFIGURATION]")
        packets = int(input("Number of packets: "))
        anomaly_rate = float(input("Anomaly rate (0.0-1.0): "))
        batch_size = int(input("Batch size (default 50): ") or "50")
        
        generator.run_simulation(
            total_packets=packets, 
            anomaly_rate=anomaly_rate,
            batch_size=batch_size,
            show_progress_every=max(100, packets // 10)
        )
    else:
        print("[ERROR] Invalid option")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[STOPPED] Traffic generator stopped by user.")
    except Exception as e:
        print(f"\n[ERROR] {e}")
        import traceback
        traceback.print_exc()