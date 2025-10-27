from app.models.device import Device
from app.database import SessionLocal
from sqlalchemy.orm import Session
from typing import Optional

# Get Device by ID
def get_device_by_id(db: Session, id: int) -> Optional[Device]:
    return db.query(Device).filter(Device.id == id).first()

# Get All Devices (with pagination)
def get_devices(db: Session, skip: int = 0, limit: int = 100):
    return db.query(Device).offset(skip).limit(limit).all()

# Create Device
def create_device(
    db: Session,
    device_name: str,
    device_type: str,
    ip_address: str,
    mac_address: str,
    status: str,
    user_id: int  # New user_id argument to associate the device with a user
) -> Device:
    db_device = Device(
        device_name=device_name,
        device_type=device_type,
        ip_address=ip_address,
        mac_address=mac_address,
        status=status,
        user_id=user_id  # Associate the device with the user
    )
    db.add(db_device)
    db.commit()
    db.refresh(db_device)
    return db_device

# Update Device by ID
def update_device_by_id(
    db: Session,
    id: int,
    device_name: Optional[str] = None,
    device_type: Optional[str] = None,
    ip_address: Optional[str] = None,
    mac_address: Optional[str] = None,
    status: Optional[str] = None,
    user_id: Optional[int] = None  # Optional user_id to allow changing user association
) -> Optional[Device]:
    db_device = get_device_by_id(db, id)
    if not db_device:
        return None

    # Update only the fields that are provided
    if device_name:
        db_device.device_name = device_name
    if device_type:
        db_device.device_type = device_type
    if ip_address:
        db_device.ip_address = ip_address
    if mac_address:
        db_device.mac_address = mac_address
    if status:
        db_device.status = status
    if user_id is not None:  # Only update user_id if provided
        db_device.user_id = user_id

    db.commit()
    db.refresh(db_device)
    return db_device

# Delete Device by ID
def delete_device_by_id(db: Session, id: int) -> bool:
    db_device = get_device_by_id(db, id)
    if db_device:
        db.delete(db_device)
        db.commit()
        return True
    return False
