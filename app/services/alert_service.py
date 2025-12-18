from sqlalchemy.orm import Session
from app.models.alert import Alert
from app.models.device import Device
from app.models.user import User
from typing import Optional
from datetime import datetime
import json
from app.services.kitsune_service import KitsuneIDSService, KITSUNE_AVAILABLE


class AlertService:
    
    def __init__(self, db: Session):
        self.db = db
        self.kitsune_service = None
    
    def initialize_kitsune(self):
        if not KITSUNE_AVAILABLE:
            return False
            
        if self.kitsune_service is None:
            try:
                self.kitsune_service = KitsuneIDSService(
                    packet_limit=100000,
                    max_autoencoder_size=10,
                    fm_grace_period=100,
                    ad_grace_period=500
                )
                return True
            except Exception as e:
                print(f"Failed to initialize Kitsune: {e}")
                return False
        return True
    
    def process_network_packet(self, packet_data: dict, user_id: int, device_id: Optional[int] = None):
        
        if not self.initialize_kitsune():
            return None
        
        detection_result = self.kitsune_service.process_packet(packet_data)
        
        if not detection_result.get('success', False):
            return None
        
        if detection_result.get('anomaly_detected', False):
            alert_data = self.kitsune_service.create_alert(detection_result)
            if alert_data:
                return self.create_alert_from_kitsune(alert_data, user_id, device_id)
        
        return None
    
    def create_alert_from_kitsune(self, kitsune_alert: dict, user_id: int, device_id: Optional[int] = None):
        
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
        
        return alert
    
    def get_kitsune_statistics(self):
        if self.kitsune_service:
            return self.kitsune_service.get_statistics()
        return None


def get_alerts(db: Session, skip: int = 0, limit: int = 100):
    return db.query(Alert).offset(skip).limit(limit).all()


def get_alerts_by_user_id(db: Session, user_id: int, skip: int = 0, limit: int = 100):
    return db.query(Alert).filter(Alert.user_id == user_id).offset(skip).limit(limit).all()


def get_alerts_by_device_id(db: Session, device_id: int, skip: int = 0, limit: int = 100):
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
    db_alert = db.query(Alert).filter(Alert.id == id).first()
    if db_alert:
        db.delete(db_alert)
        db.commit()
        return True
    return False