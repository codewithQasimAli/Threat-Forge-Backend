from sqlalchemy.orm import Session
from app.models.alert import Alert
from app.models.device import Device
from app.models.user import User
from typing import Optional
from datetime import datetime
import json
from app.services.kitsune_service import KitsuneIDSService, KITSUNE_AVAILABLE
from app.websockets.alert_websocket import alert_ws_manager 
import asyncio  

class AlertService:
    
    def __init__(self, db: Session):
        self.db = db
        self.kitsune_service = None
    
    def initialize_kitsune(self):
        """Initialize Kitsune IDS with MINIMAL settings for fast testing"""
        if not KITSUNE_AVAILABLE:
            print("WARNING: Kitsune modules not available")
            return False
            
        if self.kitsune_service is None:
            try:
                print("\n" + "="*60)
                print("INITIALIZING KITSUNE IDS SERVICE (FAST MODE)")
                print("="*60)
                
                # MINIMAL TRAINING FOR FAST TESTING - Complete in ~30 seconds
                self.kitsune_service = KitsuneIDSService(
                    packet_limit=100000,
                    max_autoencoder_size=10,
                    fm_grace_period=100,    # Just 100 packets
                    ad_grace_period=1000    # Just 1000 packets total
                )
                
                print("SUCCESS: Kitsune IDS initialized")
                print(f"  Feature mapping: 100 packets")
                print(f"  Training: 1000 packets total")
                print(f"  Expected training time: ~20 seconds")
                print("="*60 + "\n")
                
                return True
            except Exception as e:
                print(f"ERROR: Failed to initialize Kitsune: {e}")
                import traceback
                traceback.print_exc()
                return False
        return True
    
    def process_network_packet(self, packet_data: dict, user_id: int, device_id: Optional[int] = None):
        """Process a network packet through Kitsune IDS"""
        
        if not self.initialize_kitsune():
            return None
        
        # Process packet through Kitsune
        detection_result = self.kitsune_service.process_packet(packet_data)
        
        if not detection_result.get('success', False):
            return None
        
        # Create alert if anomaly detected
        if detection_result.get('anomaly_detected', False):
            alert_data = self.kitsune_service.create_alert(detection_result)
            if alert_data:
                return self.create_alert_from_kitsune(alert_data, user_id, device_id)
        
        return None
    
    def create_alert_from_kitsune(self, kitsune_alert: dict, user_id: int, device_id: Optional[int] = None):
        """Create database alert from Kitsune detection"""
        
        # Convert details dict to JSON string if needed
        details = kitsune_alert.get('details', {})
        if isinstance(details, dict):
            details = json.dumps(details)
        
        alert = Alert(
            user_id=user_id,
            device_id=device_id,
            title=kitsune_alert['title'],
            message=kitsune_alert['description'],
            severity=kitsune_alert['severity'],
            status='active',
            acknowledged=False,
            source_ip=kitsune_alert.get('source_ip'),
            dest_ip=kitsune_alert.get('dest_ip'),
            rmse_score=kitsune_alert.get('rmse_score'),
            details=details
        )
        
        self.db.add(alert)
        self.db.commit()
        self.db.refresh(alert)
        
        print(f"SUCCESS: Alert created - ID={alert.id}, Severity={alert.severity}")
        
        # Send WebSocket notification
        self._send_websocket_notification(alert, user_id)

        return alert
    
    def get_kitsune_statistics(self):
        """Get current Kitsune IDS statistics"""
        if self.kitsune_service:
            return self.kitsune_service.get_statistics()
        return None

    def _send_websocket_notification(self, alert: Alert, user_id: int):
        """Helper method to send WebSocket notification"""
        try:
            alert_dict = {
                "id": alert.id,
                "user_id": alert.user_id,
                "device_id": alert.device_id,
                "title": alert.title,
                "message": alert.message,
                "severity": alert.severity,
                "status": alert.status,
                "acknowledged": alert.acknowledged,
                "source_ip": alert.source_ip,
                "dest_ip": alert.dest_ip,
                "rmse_score": float(alert.rmse_score) if alert.rmse_score else None,
                "created_at": alert.created_at.isoformat() if alert.created_at else None,
                "acknowledged_at": alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
                "details": alert.details,
            }
            
            # Send to WebSocket
            asyncio.create_task(
                alert_ws_manager.send_alert_to_user(user_id, alert_dict)
            )
        except Exception as e:
            print(f"WebSocket notification failed: {e}")
        
# ============================================================================
# Alert CRUD Operations
# ============================================================================

def get_alerts(db: Session, skip: int = 0, limit: int = 100):
    """Get all alerts with pagination"""
    return db.query(Alert).offset(skip).limit(limit).all()


def get_alerts_by_user_id(db: Session, user_id: int, skip: int = 0, limit: int = 100):
    """Get alerts for a specific user"""
    return db.query(Alert).filter(Alert.user_id == user_id).offset(skip).limit(limit).all()


def get_alerts_by_device_id(db: Session, device_id: int, skip: int = 0, limit: int = 100):
    """Get alerts for a specific device"""
    return db.query(Alert).filter(Alert.device_id == device_id).offset(skip).limit(limit).all()


def create_alert(
    db: Session,
    user_id: int,
    device_id: Optional[int],
    title: str,
    message: str,
    severity: str,
    status: str = "active",
    acknowledged: bool = False,
    source_ip: Optional[str] = None,
    dest_ip: Optional[str] = None,
    rmse_score: Optional[float] = None,
    details: Optional[str] = None
):
    """Create a new alert manually"""
    db_alert = Alert(
        user_id=user_id,
        device_id=device_id,
        title=title,
        message=message,
        severity=severity,
        status=status,
        acknowledged=acknowledged,
        source_ip=source_ip,
        dest_ip=dest_ip,
        rmse_score=rmse_score,
        details=details
    )
    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)
    
    # Send WebSocket notification BEFORE returning
    try:
        alert_dict = {
            "id": db_alert.id,
            "user_id": db_alert.user_id,
            "device_id": db_alert.device_id,
            "title": db_alert.title,
            "message": db_alert.message,
            "severity": db_alert.severity,
            "status": db_alert.status,
            "acknowledged": db_alert.acknowledged,
            "source_ip": db_alert.source_ip,
            "dest_ip": db_alert.dest_ip,
            "rmse_score": float(db_alert.rmse_score) if db_alert.rmse_score else None,
            "created_at": db_alert.created_at.isoformat() if db_alert.created_at else None,
            "acknowledged_at": db_alert.acknowledged_at.isoformat() if db_alert.acknowledged_at else None,
            "details": db_alert.details,
        }
        
        # Send to WebSocket
        asyncio.create_task(
            alert_ws_manager.send_alert_to_user(user_id, alert_dict)
        )
    except Exception as e:
        print(f"WebSocket notification failed: {e}")
    
    # Return AFTER sending notification
    return db_alert


def update_alert_by_id(
    db: Session,
    id: int,
    title: Optional[str] = None,
    message: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    acknowledged: Optional[bool] = None,
):
    """Update an existing alert"""
    db_alert = db.query(Alert).filter(Alert.id == id).first()
    if not db_alert:
        return None

    if title:
        db_alert.title = title
    if message:
        db_alert.message = message
    if severity:
        db_alert.severity = severity
    if status:
        db_alert.status = status
    if acknowledged is not None:
        db_alert.acknowledged = acknowledged
        if acknowledged:
            db_alert.acknowledged_at = datetime.now()

    db.commit()
    db.refresh(db_alert)
    return db_alert


def delete_alert_by_id(db: Session, id: int):
    """Delete an alert by ID"""
    db_alert = db.query(Alert).filter(Alert.id == id).first()
    if db_alert:
        db.delete(db_alert)
        db.commit()
        return True
    return False