from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.database import Base
 

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    phone = Column(String, nullable=True)
    createdAt = Column(DateTime(timezone=True), server_default=func.now())
    lastlogin = Column(DateTime(timezone=True), nullable=True)

    devices = relationship("Device", back_populates="user")
    alerts = relationship("Alert", back_populates="user")