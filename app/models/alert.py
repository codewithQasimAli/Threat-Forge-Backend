from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.database import Base

class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=True)
    
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    severity = Column(String(50), nullable=False)
    status = Column(String(50), default="active")
    acknowledged = Column(Boolean, default=False)
    
    source_ip = Column(String(45), nullable=True)
    dest_ip = Column(String(45), nullable=True)
    rmse_score = Column(Float, nullable=True)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)
    
    details = Column(Text, nullable=True)
    
    user = relationship("User", back_populates="alerts")
    device = relationship("Device", back_populates="alerts")
    
    def __repr__(self):
        return f"<Alert(id={self.id}, title='{self.title}', severity='{self.severity}', acknowledged={self.acknowledged})>"