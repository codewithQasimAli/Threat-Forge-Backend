from fastapi import APIRouter, Depends, HTTPException
from app.services.device_service import (
    create_device,
    get_devices,
    get_device_by_id,
    update_device_by_id,
    delete_device_by_id,
    get_devices_by_user_id,
)
from app.database import get_db
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from app.models.device import Device

router = APIRouter()

class DeviceCreate(BaseModel):
    device_name: str
    device_type: str
    ip_address: str
    mac_address: str
    status: str
    user_id: int

class DeviceUpdate(BaseModel):
    device_name: Optional[str] = None
    device_type: Optional[str] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    status: Optional[str] = None

class DeviceResponse(BaseModel):
    id: int
    device_name: str
    device_type: str
    ip_address: str
    mac_address: str
    status: str
    created_at: datetime
    user_id: int

    class Config:
        from_attributes = True

class DeleteMessage(BaseModel):
    message: str


# CREATE DEVICE WITH DUPLICATE VALIDATION
@router.post("/device", response_model=DeviceResponse)
def create_device_route(device: DeviceCreate, db: Session = Depends(get_db)):
    # Check for duplicate IP address (per user)
    existing_ip = db.query(Device).filter(
        Device.user_id == device.user_id,
        Device.ip_address == device.ip_address
    ).first()
    
    if existing_ip:
        raise HTTPException(
            status_code=400,
            detail=f"Device with IP address {device.ip_address} already exists for this user"
        )
    
    # Check for duplicate MAC address (per user)
    # Normalize MAC address to uppercase for comparison
    normalized_mac = device.mac_address.upper().replace('-', ':')
    
    existing_mac = db.query(Device).filter(
        Device.user_id == device.user_id,
        Device.mac_address == normalized_mac
    ).first()
    
    if existing_mac:
        raise HTTPException(
            status_code=400,
            detail=f"Device with MAC address {device.mac_address} already exists for this user"
        )
    
    # Create device if no duplicates
    db_device = create_device(
        db=db, 
        device_name=device.device_name,
        device_type=device.device_type,
        ip_address=device.ip_address,
        mac_address=normalized_mac,  # Store normalized MAC
        status=device.status,
        user_id=device.user_id
    )
    return db_device


# Get Device by ID
@router.get("/device/{id}", response_model=DeviceResponse)
def get_device_route(id: int, db: Session = Depends(get_db)):
    db_device = get_device_by_id(db=db, id=id)
    if db_device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    
    device_payload = {
        "id": db_device.id,
        "device_name": db_device.device_name,
        "device_type": db_device.device_type,
        "ip_address": db_device.ip_address,
        "mac_address": db_device.mac_address,
        "status": db_device.status,
        "created_at": db_device.created_at,
        "user_id": db_device.user_id,
    }

    return device_payload


# Get All Devices
@router.get("/devices/all", response_model=list[DeviceResponse])
def get_devices_route(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    devices = get_devices(db=db, skip=skip, limit=limit)
    return devices


# Get all devices for a user
@router.get("/devices/user/{user_id}", response_model=list[DeviceResponse])
def get_user_devices(user_id: int, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    devices = get_devices_by_user_id(db=db, user_id=user_id, skip=skip, limit=limit)
    return devices


# UPDATE DEVICE WITH DUPLICATE VALIDATION
@router.put("/device/{id}", response_model=DeviceResponse)
def update_device_route(id: int, device: DeviceUpdate, db: Session = Depends(get_db)):
    # ✅ Get existing device
    existing_device = get_device_by_id(db=db, id=id)
    if existing_device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    
    update_data = device.dict(exclude_unset=True)
    
    # Check for duplicate IP (if IP is being changed)
    if 'ip_address' in update_data:
        new_ip = update_data['ip_address']
        if new_ip != existing_device.ip_address:
            duplicate_ip = db.query(Device).filter(
                Device.user_id == existing_device.user_id,
                Device.ip_address == new_ip,
                Device.id != id  # Exclude current device
            ).first()
            
            if duplicate_ip:
                raise HTTPException(
                    status_code=400,
                    detail=f"Device with IP address {new_ip} already exists for this user"
                )
    
    # Check for duplicate MAC (if MAC is being changed)
    if 'mac_address' in update_data:
        normalized_mac = update_data['mac_address'].upper().replace('-', ':')
        if normalized_mac != existing_device.mac_address:
            duplicate_mac = db.query(Device).filter(
                Device.user_id == existing_device.user_id,
                Device.mac_address == normalized_mac,
                Device.id != id  # Exclude current device
            ).first()
            
            if duplicate_mac:
                raise HTTPException(
                    status_code=400,
                    detail=f"Device with MAC address {update_data['mac_address']} already exists for this user"
                )
        
        # Store normalized MAC
        update_data['mac_address'] = normalized_mac
    
    # Update device if no duplicates
    db_device = update_device_by_id(db=db, id=id, **update_data)
    return db_device


# Delete Device by ID
@router.delete("/device/{id}", response_model=DeleteMessage)
def delete_device_route(id: int, db: Session = Depends(get_db)):
    success = delete_device_by_id(db=db, id=id)
    
    if not success:
        raise HTTPException(status_code=404, detail="Device not found")
    
    return {"message": "Device deleted successfully"}