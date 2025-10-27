from sqlalchemy.orm import Session
from app.models.alert import Alert
from app.models.device import Device
from app.models.user import User
from typing import Optional

# Get all alerts with pagination
def get_alerts(db: Session, skip: int = 0, limit: int = 100):
    return db.query(Alert).offset(skip).limit(limit).all()

# Get alerts by user id
def get_alerts_by_user_id(db: Session, user_id: int, skip: int = 0, limit: int = 100):
    return db.query(Alert).filter(Alert.user_id == user_id).offset(skip).limit(limit).all()

# Get alerts by device id
def get_alerts_by_device_id(db: Session, device_id: int, skip: int = 0, limit: int = 100):
    return db.query(Alert).filter(Alert.device_id == device_id).offset(skip).limit(limit).all()

# Create a new alert
def create_alert(
    db: Session,
    user_id: int,
    device_id: int,
    title: str,
    message: str,
    severity: str,
    status: str = "active"
):
    db_alert = Alert(
        user_id=user_id,
        device_id=device_id,
        title=title,
        message=message,
        severity=severity,
        status=status
    )
    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)
    return db_alert

# Update an alert by ID
def update_alert_by_id(
    db: Session,
    id: int,
    title: Optional[str] = None,
    message: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None
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

    db.commit()
    db.refresh(db_alert)
    return db_alert

# Delete an alert by ID
def delete_alert_by_id(db: Session, id: int):
    db_alert = db.query(Alert).filter(Alert.id == id).first()
    if db_alert:
        db.delete(db_alert)
        db.commit()
        return True
    return False
