import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, DateTime, Boolean
from app.database import Base

class NetworkLog(Base):
    __tablename__ = "network_logs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    simulation_run_id = Column(String, nullable=True)
    src_ip = Column(String, nullable=True)
    dst_ip = Column(String, nullable=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(Integer, nullable=True)
    flow_duration = Column(Float, nullable=True)
    packet_count = Column(Integer, nullable=True)
    rmse_score = Column(Float, nullable=True)
    is_anomaly = Column(Boolean, default=False)
    severity = Column(String, default="none")
    timestamp = Column(DateTime, default=datetime.utcnow)
