from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Enum
from sqlalchemy.orm import relationship
from enum import Enum as PyEnum  # Import Python's Enum class for DeviceStatus
from datetime import datetime
from app.database import Base
from sqlalchemy.sql import func

# Define an Enum for DeviceStatus (You should replace this with actual status values)
class DeviceStatus(PyEnum):
    active = "active"
    inactive = "inactive"
    pending = "pending"

class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))  # Foreign key linking to the User table
    device_name = Column(String)
    device_type = Column(String)
    ip_address = Column(String)
    mac_address = Column(String)
    status = Column(Enum(DeviceStatus), default=DeviceStatus.inactive)  # Enum column for status
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    

    # Establishing the relationship to User model
    def __init__(self, *args, **kwargs):
        from app.models.user import User  # Import inside the method to avoid circular import
        self.user = relationship("User", back_populates="devices")
        super().__init__(*args, **kwargs)

    alerts = relationship("Alert", back_populates="device")