from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Enum
from sqlalchemy.orm import relationship
from enum import Enum as PyEnum  # Import Python's Enum class for DeviceStatus
from datetime import datetime
from app.database import Base
from sqlalchemy.sql import func

class DeviceStatus(PyEnum):
    active = "active"
    inactive = "inactive"
    pending = "pending"

class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))  
    device_name = Column(String)
    device_type = Column(String)
    ip_address = Column(String)
    mac_address = Column(String)
    status = Column(Enum(DeviceStatus), default=DeviceStatus.inactive) 
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    

    user = relationship("User", back_populates="devices")
    alerts = relationship("Alert", back_populates="device")