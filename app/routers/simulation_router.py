from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.simulation import SimulationRun

router = APIRouter()

@router.get("/simulation/history")
def get_simulation_history(limit: int = 10, db: Session = Depends(get_db)):
    runs = db.query(SimulationRun).order_by(SimulationRun.timestamp.desc()).limit(limit).all()
    return [
        {
            "id": r.id,
            "timestamp": r.timestamp.isoformat(),
            "attack_types": r.attack_types,
            "total_flows": r.total_flows,
            "anomalies_detected": r.anomalies_detected,
            "alerts_created": r.alerts_created,
            "pcap_file": r.pcap_file,
            "status": r.status,
            "duration_seconds": r.duration_seconds,
        }
        for r in runs
    ]

@router.get("/simulation/latest")
def get_latest_simulation(db: Session = Depends(get_db)):
    run = db.query(SimulationRun).order_by(SimulationRun.timestamp.desc()).first()
    if not run:
        raise HTTPException(status_code=404, detail="No simulation runs found")
    return {
        "id": run.id,
        "timestamp": run.timestamp.isoformat(),
        "attack_types": run.attack_types,
        "total_flows": run.total_flows,
        "anomalies_detected": run.anomalies_detected,
        "alerts_created": run.alerts_created,
        "pcap_file": run.pcap_file,
        "status": run.status,
        "duration_seconds": run.duration_seconds,
    }

@router.get("/simulation/status")
def get_simulation_status():
    return {"status": "ready", "message": "Simulation pipeline operational"}
