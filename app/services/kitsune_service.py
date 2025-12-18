import sys
import os
import numpy as np
from datetime import datetime
import inspect

# Get the current file's directory (app/services)
current_file = os.path.abspath(__file__)
services_dir = os.path.dirname(current_file)

# FIXED: Kitsune-py is in the services folder at backend root
backend_root = os.path.dirname(os.path.dirname(services_dir))
kitsune_path = os.path.join(backend_root, 'services', 'Kitsune-py')

print(f"Current file: {current_file}")
print(f"Services dir: {services_dir}")
print(f"Backend root: {backend_root}")
print(f"Kitsune path: {kitsune_path}")
print(f"Kitsune path exists: {os.path.exists(kitsune_path)}")

if os.path.exists(kitsune_path):
    sys.path.insert(0, kitsune_path)
    print(f"Added to Python path: {kitsune_path}")
else:
    print(f"WARNING: Kitsune path does not exist: {kitsune_path}")

try:
    # Import the correct modules - FeatureExtractor and netStat handle AfterImage internally
    from KitNET.KitNET import KitNET
    import netStat as ns
    print("✓ Successfully imported Kitsune modules (KitNET and netStat)")
    KITSUNE_AVAILABLE = True
except ImportError as e:
    print(f"✗ Warning: Could not import Kitsune modules: {e}")
    KitNET = None
    ns = None
    KITSUNE_AVAILABLE = False


class KitsuneIDSService:
    """
    Kitsune Intrusion Detection System Service
    Uses ensemble of autoencoders for network anomaly detection
    """
    
    def __init__(self, packet_limit=100000, max_autoencoder_size=10, 
                 fm_grace_period=5000, ad_grace_period=50000):
        """
        Initialize the Kitsune IDS Service
        
        Args:
            packet_limit: Maximum number of packets to process
            max_autoencoder_size: Maximum size for any autoencoder in ensemble
            fm_grace_period: Feature mapping grace period (packets)
            ad_grace_period: Anomaly detection training grace period (packets)
        """
        if not KITSUNE_AVAILABLE:
            raise RuntimeError("Kitsune modules are not available")
            
        self.packet_limit = packet_limit
        self.max_autoencoder_size = max_autoencoder_size
        self.fm_grace_period = fm_grace_period
        self.ad_grace_period = ad_grace_period
        
        # Initialize network statistics tracker (handles AfterImage internally)
        self.netstat = ns.netStat()
        
        # Debug: Check the signature of updateGetStats
        try:
            sig = inspect.signature(self.netstat.updateGetStats)
            print(f"\n[DEBUG] updateGetStats signature: {sig}")
            print(f"[DEBUG] Parameters: {list(sig.parameters.keys())}")
        except:
            pass
        
        self.kitnet = None
        self.packet_count = 0
        self.anomaly_threshold = 0.1
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'anomalies_detected': 0,
            'false_positives': 0,
            'training_complete': False
        }
        
    def extract_features(self, packet_data):
        """
        Extract features from packet data using netStat (which uses AfterImage)
        
        Args:
            packet_data: Dictionary containing packet information
            
        Returns:
            Feature vector or None if extraction fails
        """
        try:
            # Get basic packet information
            src_ip = str(packet_data.get('source_ip', '0.0.0.0'))
            dst_ip = str(packet_data.get('dest_ip', '0.0.0.0'))
            src_port = packet_data.get('source_port', 0)
            dst_port = packet_data.get('dest_port', 0)
            
            # Use IP addresses as MAC addresses (simplified)
            src_mac = src_ip
            dst_mac = dst_ip
            
            # IMPORTANT: srcProtocol and dstProtocol must be STRINGS
            # They represent the protocol/port and will be concatenated with IP
            src_proto = str(src_port)
            dst_proto = str(dst_port)
            
            datagram_size = int(packet_data.get('length', 0))
            timestamp = float(packet_data.get('timestamp', datetime.now().timestamp()))
            
            # IPtype: 0 for IPv4, 1 for IPv6 (we'll use 0 for IPv4)
            ip_type = 0
            
            # Call updateGetStats with correct signature:
            # (IPtype, srcMAC, dstMAC, srcIP, srcProtocol, dstIP, dstProtocol, datagramSize, timestamp)
            features = self.netstat.updateGetStats(
                ip_type,
                src_mac,
                dst_mac,
                src_ip,
                src_proto,
                dst_ip,
                dst_proto,
                datagram_size,
                timestamp
            )
            
            # features is already a numpy array or list, check if it's not None and has elements
            if features is not None and len(features) > 0:
                return np.array(features)
            else:
                return None
            
        except Exception as e:
            print(f"Error extracting features: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def process_packet(self, packet_data):
        """
        Process a network packet through Kitsune IDS
        
        Args:
            packet_data: Dictionary with packet information
            
        Returns:
            Dictionary with detection results
        """
        self.packet_count += 1
        self.stats['total_packets'] = self.packet_count
        
        # Extract features from packet
        features = self.extract_features(packet_data)
        
        if features is None or len(features) == 0:
            return {
                'success': False,
                'anomaly_detected': False,
                'rmse': 0,
                'message': 'Feature extraction failed or returned empty features'
            }
        
        # Initialize KitNET on first successful feature extraction
        if self.kitnet is None:
            print(f"\n[Initializing KitNET]")
            print(f"  Number of features: {len(features)}")
            print(f"  Max autoencoder size: {self.max_autoencoder_size}")
            print(f"  FM grace period: {self.fm_grace_period}")
            print(f"  AD grace period: {self.ad_grace_period}")
            
            try:
                self.kitnet = KitNET(
                    len(features),
                    self.max_autoencoder_size,
                    self.fm_grace_period,
                    self.ad_grace_period
                )
                print("✓ KitNET initialized successfully")
            except Exception as e:
                print(f"✗ Failed to initialize KitNET: {e}")
                import traceback
                traceback.print_exc()
                return {
                    'success': False,
                    'anomaly_detected': False,
                    'rmse': 0,
                    'message': f'KitNET initialization failed: {str(e)}'
                }
        
        # Process through KitNET
        try:
            rmse = self.kitnet.process(features)
            
            # Determine if anomaly
            is_anomaly = False
            if rmse is not None and rmse > self.anomaly_threshold:
                # Only flag as anomaly after training period
                if self.packet_count > self.ad_grace_period:
                    is_anomaly = True
                    self.stats['anomalies_detected'] += 1
            
            # Update training status
            if self.packet_count > self.ad_grace_period:
                self.stats['training_complete'] = True
            
            return {
                'success': True,
                'anomaly_detected': is_anomaly,
                'rmse': float(rmse) if rmse is not None else 0,
                'threshold': self.anomaly_threshold,
                'packet_count': self.packet_count,
                'source_ip': packet_data.get('source_ip'),
                'dest_ip': packet_data.get('dest_ip'),
                'timestamp': packet_data.get('timestamp'),
                'training_phase': self._get_training_phase(),
                'progress_percentage': self._get_progress_percentage()
            }
        except Exception as e:
            print(f"✗ Error processing packet through KitNET: {e}")
            import traceback
            traceback.print_exc()
            return {
                'success': False,
                'anomaly_detected': False,
                'rmse': 0,
                'message': f'KitNET processing error: {str(e)}'
            }
    
    def _get_training_phase(self):
        """Get current training phase"""
        if self.packet_count <= self.fm_grace_period:
            return 'feature_mapping'
        elif self.packet_count <= self.ad_grace_period:
            return 'training'
        else:
            return 'detection'
    
    def _get_progress_percentage(self):
        """Get training progress percentage"""
        if self.packet_count >= self.ad_grace_period:
            return 100.0
        return (self.packet_count / self.ad_grace_period) * 100
    
    def create_alert(self, detection_result):
        """
        Create an alert from detection result
        
        Args:
            detection_result: Result from process_packet()
            
        Returns:
            Alert dictionary or None
        """
        if not detection_result.get('anomaly_detected', False):
            return None
        
        # Determine severity based on RMSE score
        rmse = detection_result.get('rmse', 0)
        if rmse > self.anomaly_threshold * 3:
            severity = 'critical'
        elif rmse > self.anomaly_threshold * 2:
            severity = 'high'
        else:
            severity = 'medium'
        
        alert = {
            'title': f"Anomaly Detected: {detection_result.get('source_ip', 'unknown')} → {detection_result.get('dest_ip', 'unknown')}",
            'description': f"Network anomaly detected with RMSE score of {rmse:.4f} (threshold: {self.anomaly_threshold})",
            'severity': severity,
            'source_ip': detection_result.get('source_ip'),
            'dest_ip': detection_result.get('dest_ip'),
            'rmse_score': rmse,
            'timestamp': datetime.now(),
            'acknowledged': False,
            'details': {
                'packet_count': detection_result.get('packet_count'),
                'threshold': detection_result.get('threshold'),
                'detection_time': detection_result.get('timestamp'),
                'training_phase': detection_result.get('training_phase')
            }
        }
        
        return alert
    
    def get_statistics(self):
        """Get current IDS statistics"""
        return {
            'total_packets': self.stats['total_packets'],
            'anomalies_detected': self.stats['anomalies_detected'],
            'training_complete': self.stats['training_complete'],
            'training_phase': self._get_training_phase(),
            'progress_percentage': self._get_progress_percentage(),
            'fm_grace_period': self.fm_grace_period,
            'ad_grace_period': self.ad_grace_period,
            'anomaly_threshold': self.anomaly_threshold
        }


def test_kitsune_service():
    """Test the Kitsune IDS Service"""
    
    print("\n" + "="*60)
    print("KITSUNE IDS SERVICE TEST")
    print("="*60 + "\n")
    
    if not KITSUNE_AVAILABLE:
        print("✗ Kitsune modules not available")
        print("\nEnsure Kitsune-py repository contains:")
        print("  - KitNET/KitNET.py")
        print("  - netStat.py")
        print(f"\nExpected path: {kitsune_path}")
        return
    
    print("✓ Kitsune modules imported successfully\n")
    
    print("[Step 1] Initializing Kitsune IDS Service...")
    try:
        kitsune_service = KitsuneIDSService(
            packet_limit=100000,
            max_autoencoder_size=10,
            fm_grace_period=100,  # Reduced for testing
            ad_grace_period=200   # Reduced for testing
        )
        print("✓ Service initialized successfully\n")
    except Exception as e:
        print(f"✗ Failed to initialize service: {e}")
        import traceback
        traceback.print_exc()
        return
    
    print("[Step 2] Processing test packets...\n")
    
    # Create varied test packets
    test_packets = [
        {
            'timestamp': datetime.now().timestamp(),
            'source_ip': '192.168.1.100',
            'dest_ip': '192.168.1.1',
            'source_port': 54321,
            'dest_port': 80,
            'protocol': 'TCP',
            'length': 64
        },
        {
            'timestamp': datetime.now().timestamp() + 0.1,
            'source_ip': '192.168.1.101',
            'dest_ip': '8.8.8.8',
            'source_port': 12345,
            'dest_port': 443,
            'protocol': 'TCP',
            'length': 1500
        },
        {
            'timestamp': datetime.now().timestamp() + 0.2,
            'source_ip': '10.0.0.5',
            'dest_ip': '10.0.0.1',
            'source_port': 8080,
            'dest_port': 22,
            'protocol': 'TCP',
            'length': 128
        }
    ]
    
    for i, packet in enumerate(test_packets, 1):
        try:
            result = kitsune_service.process_packet(packet)
            
            if result.get('success', False):
                print(f"  Packet {i}: ✓")
                print(f"    Source: {packet['source_ip']}:{packet['source_port']}")
                print(f"    Dest: {packet['dest_ip']}:{packet['dest_port']}")
                print(f"    RMSE: {result['rmse']:.6f}")
                print(f"    Anomaly: {'YES ' if result['anomaly_detected'] else 'NO ✓'}")
                print(f"    Phase: {result.get('training_phase', 'unknown')}")
                print(f"    Progress: {result.get('progress_percentage', 0):.1f}%")
                
                if result['anomaly_detected']:
                    alert = kitsune_service.create_alert(result)
                    if alert:
                        print(f"    Alert: {alert['title']}")
                        print(f"    Severity: {alert['severity']}")
            else:
                print(f"  Packet {i}: ✗ {result.get('message', 'Unknown error')}")
            print()
        except Exception as e:
            print(f"  ✗ Error processing packet {i}: {e}")
            import traceback
            traceback.print_exc()
            print()
    
    print("[Step 3] Getting statistics...")
    stats = kitsune_service.get_statistics()
    print(f"  Total packets: {stats['total_packets']}")
    print(f"  Anomalies detected: {stats['anomalies_detected']}")
    print(f"  Training complete: {stats['training_complete']}")
    print(f"  Current phase: {stats['training_phase']}")
    print(f"  Progress: {stats['progress_percentage']:.1f}%")
    
    print("\n" + "="*60)
    print("TEST COMPLETED SUCCESSFULLY ✓")
    print("="*60 + "\n")


if __name__ == "__main__":
    test_kitsune_service()