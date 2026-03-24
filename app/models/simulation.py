import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, DateTime, JSON
from app.database import Base

class SimulationRun(Base):
    __tablename__ = "simulation_runs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, default=datetime.utcnow)
    attack_types = Column(JSON, default=list)
    total_flows = Column(Integer, default=0)
    anomalies_detected = Column(Integer, default=0)
    alerts_created = Column(Integer, default=0)
    pcap_file = Column(String, nullable=True)
    status = Column(String, default="completed")
    duration_seconds = Column(Integer, default=30)
    results_json = Column(JSON, nullable=True)
