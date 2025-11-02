from sqlalchemy import Column, Integer, String, Enum, ForeignKey, DateTime, Boolean
from sqlalchemy.orm import relationship
from app.database import Base
from datetime import datetime
from enum import Enum as PyEnum  # Import Enum from Python's enum module

# Define the status Enum with a name
class AlertStatus(PyEnum):
    active = "active"
    inactive = "inactive"

class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    device_id = Column(Integer, ForeignKey("devices.id"))
    title = Column(String)
    message = Column(String)
    severity = Column(String)
    status = Column(Enum(AlertStatus, name="alert_status_enum"), default=AlertStatus.active)  # Added name to Enum
    acknowledged = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="alerts")
    device = relationship("Device", back_populates="alerts")
