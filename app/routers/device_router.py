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
from app.models.device import Device  # Ensure you import the Device model

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

class DeleteMessage(BaseModel):
    message: str


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
@router.get("/device/{id}", response_model=DeviceResponse)
def get_device_route(id: int, db: Session = Depends(get_db)):
    db_device = get_device_by_id(db=db, id=id)
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


# Get all devices for a user
@router.get("/devices/user/{user_id}", response_model=list[DeviceResponse])
def get_user_devices(user_id: int, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    devices = get_devices_by_user_id(db=db, user_id=user_id, skip=skip, limit=limit)
    return devices


# Update Device by ID
@router.put("/device/{id}", response_model=DeviceResponse)
def update_device_route(id: int, device: DeviceUpdate, db: Session = Depends(get_db)):
    db_device = update_device_by_id(db=db, id=id, **device.dict(exclude_unset=True))
    if db_device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return db_device


# Delete Device by ID
@router.delete("/device/{id}", response_model=DeleteMessage)
def delete_device_route(id: int, db: Session = Depends(get_db)):
    db_device = delete_device_by_id(db=db, id=id)
    if not db_device:
        raise HTTPException(status_code=404, detail="Device not found")

    # Delete the device from the database
    db.delete(db_device)
    db.commit()

    # Return the deleted device details
    return {
        "id": db_device.id,
        "user_id": db_device.user_id,
        "device_name": db_device.device_name,
        "device_type": db_device.device_type,
        "ip_address": db_device.ip_address,
        "mac_address": db_device.mac_address,
        "status": db_device.status,
        "created_at": db_device.created_at
    }
