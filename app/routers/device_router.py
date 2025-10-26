from fastapi import APIRouter, Depends, HTTPException
from app.services.device_service import (
    create_device,
    get_devices,
    get_device_by_id,
    update_device_by_id,
    delete_device_by_id,
)
from app.database import get_db
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

router = APIRouter()

class DeviceCreate(BaseModel):
    device_name: str
    device_type: str
    ip_address: str
    mac_address: str
    status: str
    user_id: int  # New field for the foreign key reference to User

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
    user_id: int  # Include user_id in the response

    class Config:
        from_attributes = True


# Create Device
@router.post("/device", response_model=DeviceResponse)
def create_device_route(device: DeviceCreate, db: Session = Depends(get_db)):
    db_device = create_device(
        db=db, 
        device_name=device.device_name,
        device_type=device.device_type,
        ip_address=device.ip_address,
        mac_address=device.mac_address,
        status=device.status,
        user_id=device.user_id  # Pass user_id to associate the device with a user
    )
    return db_device


# Get Device by ID
@router.get("/devices/{device_id}", response_model=DeviceResponse)
def get_device_route(device_id: int, db: Session = Depends(get_db)):
    db_device = get_device_by_id(db=db, device_id=device_id)
    if db_device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    
    # Dynamically add last_seen and updated_at
    device_payload = {
        "id": db_device.id,
        "device_name": db_device.device_name,
        "device_type": db_device.device_type,
        "ip_address": db_device.ip_address,
        "mac_address": db_device.mac_address,
        "status": db_device.status,
        "created_at": db_device.created_at,
        "user_id": db_device.user_id,  # Include user_id in the response
    }

    return device_payload

# Get All Devices
@router.get("/devices/all", response_model=list[DeviceResponse])
def get_devices_route(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    devices = get_devices(db=db, skip=skip, limit=limit)
    return devices


# Update Device by ID
@router.put("/devices/{device_id}", response_model=DeviceResponse)
def update_device_route(device_id: int, device: DeviceUpdate, db: Session = Depends(get_db)):
    db_device = update_device_by_id(db=db, device_id=device_id, **device.dict(exclude_unset=True))
    if db_device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return db_device


# Delete Device by ID
@router.delete("/devices/{device_id}", response_model=DeviceResponse)
def delete_device_route(device_id: int, db: Session = Depends(get_db)):
    db_device = delete_device_by_id(db=db, device_id=device_id)
    if not db_device:
        raise HTTPException(status_code=404, detail="Device not found")
    return {"message": "Device deleted successfully"}
