import random
import time
from datetime import datetime
import requests
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

class TrafficGenerator:
    
    def __init__(self, api_url="http://localhost:8000", user_id=1, device_id=None):
        self.api_url = api_url
        self.user_id = user_id
        self.device_id = device_id
        self.normal_ips = [f"192.168.1.{i}" for i in range(10, 50)]
        self.server_ips = ["192.168.1.1", "8.8.8.8", "1.1.1.1", "10.0.0.1"]
        self.common_ports = [80, 443, 22, 3306, 5432, 8080]
        self.stats_lock = Lock()
        self.successful = 0
        self.failed = 0
        self.anomalies_generated = 0
        
    def generate_normal_packet(self):
        return {
            'user_id': self.user_id,
            'device_id': self.device_id,
            'timestamp': datetime.now().timestamp(),
            'source_ip': random.choice(self.normal_ips),
            'dest_ip': random.choice(self.server_ips),
            'source_port': random.randint(1024, 65535),
            'dest_port': random.choice(self.common_ports),
            'protocol': 'TCP',
            'length': random.randint(64, 1500)
        }
    
    def generate_anomalous_packet(self):
        """Generate various types of anomalous packets"""
        packet = self.generate_normal_packet()
        
        anomaly_type = random.choice([
            'large_packet', 
            'unusual_port', 
            'high_frequency',
            'port_scan',
            'suspicious_combo'
        ])
        
        if anomaly_type == 'large_packet':
            packet['length'] = random.randint(5000, 9000)
        elif anomaly_type == 'unusual_port':
            packet['dest_port'] = random.randint(10000, 60000)
        elif anomaly_type == 'high_frequency':
            packet['source_ip'] = "192.168.1.99"
        elif anomaly_type == 'port_scan':
            packet['source_ip'] = "192.168.1.98"
            packet['dest_port'] = random.randint(1, 1024)
        elif anomaly_type == 'suspicious_combo':
            packet['dest_port'] = 23
            packet['length'] = random.randint(2000, 3000)
        
        return packet
    
    def send_packet(self, packet):
        """Send a single packet and return success status"""
        try:
            response = requests.post(
                f"{self.api_url}/alerts/kitsune/process-packet",
                json=packet,
                timeout=10  # Increased timeout
            )
            return response.status_code in [200, 201]
        except Exception as e:
            return False
    
    def send_packet_batch(self, packet_data):
        """Send a packet and update stats thread-safely"""
        packet, is_anomaly = packet_data
        success = self.send_packet(packet)
        
        with self.stats_lock:
            if success:
                self.successful += 1
            else:
                self.failed += 1
            if is_anomaly:
                self.anomalies_generated += 1
        
        return success
    
    def run_simulation(self, total_packets=1000, anomaly_rate=0.05, delay=0.01, 
                       show_progress_every=100, max_workers=10):
        print(f"\n{'='*60}")
        print(f"TRAFFIC SIMULATION STARTING")
        print(f"{'='*60}")
        print(f"  Total packets: {total_packets}")
        print(f"  User ID: {self.user_id}")
        print(f"  Device ID: {self.device_id}")
        print(f"  Anomaly rate: {anomaly_rate * 100}%")
        print(f"  Delay: {delay}s per packet")
        print(f"  Concurrent workers: {max_workers}")
        print(f"  Estimated time: {total_packets * delay / max_workers:.1f} seconds")
        print(f"  Target: {self.api_url}")
        print(f"{'='*60}\n")
        
        # Reset stats
        self.successful = 0
        self.failed = 0
        self.anomalies_generated = 0
        start_time = time.time()
        
        # Prepare all packets
        packets_to_send = []
        for i in range(total_packets):
            is_anomaly = random.random() < anomaly_rate
            if is_anomaly:
                packet = self.generate_anomalous_packet()
            else:
                packet = self.generate_normal_packet()
            packets_to_send.append((packet, is_anomaly))
        
        # Send packets concurrently
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            
            for i, packet_data in enumerate(packets_to_send, 1):
                future = executor.submit(self.send_packet_batch, packet_data)
                futures.append(future)
                
                # Rate limiting
                time.sleep(delay)
                
                # Show progress
                if i % show_progress_every == 0 or i == total_packets:
                    # Wait for pending requests to complete
                    completed = sum(1 for f in futures if f.done())
                    
                    elapsed = time.time() - start_time
                    packets_per_sec = i / elapsed if elapsed > 0 else 0
                    
                    print(f"\n--- Progress: {i}/{total_packets} packets ({i*100//total_packets}%) ---")
                    print(f"  Sent: {i}, Completed: {completed}")
                    print(f"  Success: {self.successful}, Failed: {self.failed}")
                    print(f"  Anomalies generated: {self.anomalies_generated}")
                    print(f"  Speed: {packets_per_sec:.1f} packets/sec")
                    print(f"  Elapsed: {elapsed:.1f}s")
                    
                    # Get Kitsune statistics
                    self._print_kitsune_stats()
            
            # Wait for all to complete
            print("\nWaiting for all requests to complete...")
            for future in as_completed(futures):
                pass
        
        # Final summary
        elapsed = time.time() - start_time
        print(f"\n{'='*60}")
        print(f"SIMULATION COMPLETED!")
        print(f"{'='*60}")
        print(f"  Total sent: {self.successful}/{total_packets}")
        print(f"  Failed: {self.failed}")
        print(f"  Anomalies generated: {self.anomalies_generated}")
        print(f"  Total time: {elapsed:.1f} seconds")
        print(f"  Average speed: {total_packets/elapsed:.1f} packets/sec")
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
                
                print(f"  Kitsune phase: {phase}")
                print(f"  Training progress: {progress:.1f}%")
                print(f"  Anomalies detected: {detected}")
                
                if phase == 'feature_mapping':
                    print(f"  Status: Learning network structure...")
                elif phase == 'training':
                    print(f"  Status: Training autoencoders...")
                elif phase == 'detection':
                    print(f"  Status: Active detection mode!")
        except:
            pass
    
    def _print_alerts(self):
        """Helper to print alerts summary"""
        try:
            alerts_response = requests.get(
                f"{self.api_url}/alerts/alerts/user/{self.user_id}",
                timeout=5
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
                        print(f"  {sev}: {count}")
                    
                    print(f"\nView all alerts:")
                    print(f"  GET {self.api_url}/alerts/alerts/user/{self.user_id}")
                else:
                    print(f"\nNo alerts yet. Kitsune may still be training.")
        except Exception as e:
            print(f"Could not fetch alerts: {e}")


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
    print("FAST OPTIONS (Recommended for testing with fm=100, ad=500):")
    print("  1. Quick test (100 packets, ~1-2 sec)")
    print("  2. Complete training (600 packets, ~5 sec)")
    print("  3. Detection test (500 packets, 20% anomalies, ~5 sec)")
    print()
    print("SLOWER OPTIONS (For higher accuracy settings):")
    print("  4. Medium training (5000 packets, ~30 sec)")
    print("  5. Full training (50000 packets, ~5 min)")
    print()
    print("OTHER:")
    print("  6. Custom configuration")
    print("="*60)
    
    choice = input("\nSelect option (1-6): ").strip()
    
    if choice == "1":
        print("\n[QUICK TEST MODE]")
        generator.run_simulation(
            total_packets=100, 
            anomaly_rate=0.05, 
            delay=0.001,
            show_progress_every=50,
            max_workers=20
        )
        
    elif choice == "2":
        print("\n[COMPLETE TRAINING MODE]")
        generator.run_simulation(
            total_packets=600, 
            anomaly_rate=0.02, 
            delay=0.001,
            show_progress_every=100,
            max_workers=20
        )
        print("\n[SUCCESS] Training should be complete!")
        print("Now run option 3 (Detection test)!")
        
    elif choice == "3":
        print("\n[DETECTION TEST MODE]")
        print("Sending HIGH anomaly rate for detection testing.")
        generator.run_simulation(
            total_packets=500, 
            anomaly_rate=0.2,
            delay=0.001,
            show_progress_every=100,
            max_workers=20
        )
        
    elif choice == "4":
        print("\n[MEDIUM TRAINING MODE]")
        generator.run_simulation(
            total_packets=5000, 
            anomaly_rate=0.02, 
            delay=0.001,
            show_progress_every=500,
            max_workers=50
        )
        
    elif choice == "5":
        print("\n[FULL TRAINING MODE]")
        confirm = input("This will take ~5 minutes. Continue? (y/n): ").strip().lower()
        if confirm == 'y':
            generator.run_simulation(
                total_packets=50000, 
                anomaly_rate=0.02, 
                delay=0.001,
                show_progress_every=5000,
                max_workers=50
            )
        
    elif choice == "6":
        print("\n[CUSTOM CONFIGURATION]")
        packets = int(input("Number of packets: "))
        anomaly_rate = float(input("Anomaly rate (0.0-1.0): "))
        delay = float(input("Delay between packets (seconds): "))
        workers = int(input("Concurrent workers (10-50): ") or "20")
        
        generator.run_simulation(
            total_packets=packets, 
            anomaly_rate=anomaly_rate, 
            delay=delay,
            show_progress_every=100,
            max_workers=workers
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