from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import Integer
from app.database import get_db
from app.models.network_log import NetworkLog
from typing import Optional

router = APIRouter()

@router.get("/logs/network")
def get_network_logs(
    severity: Optional[str] = None,
    is_anomaly: Optional[bool] = None,
    user_id: Optional[str] = None,
    limit: int = 50,
    db: Session = Depends(get_db)
):
    query = db.query(NetworkLog).order_by(NetworkLog.timestamp.desc())
    if user_id:
        query = query.filter(NetworkLog.user_id == user_id)
    if severity:
        query = query.filter(NetworkLog.severity == severity)
    if is_anomaly is not None:
        query = query.filter(NetworkLog.is_anomaly == is_anomaly)
    logs = query.limit(limit).all()
    return [
        {
            "id": l.id,
            "simulation_run_id": l.simulation_run_id,
            "src_ip": l.src_ip,
            "dst_ip": l.dst_ip,
            "src_port": l.src_port,
            "dst_port": l.dst_port,
            "protocol": l.protocol,
            "flow_duration": l.flow_duration,
            "packet_count": l.packet_count,
            "rmse_score": l.rmse_score,
            "is_anomaly": l.is_anomaly,
            "severity": l.severity,
            "timestamp": l.timestamp.isoformat(),
        }
        for l in logs
    ]

@router.get("/logs/network/stats")
def get_network_log_stats(user_id: Optional[str] = None, db: Session = Depends(get_db)):
    base = db.query(NetworkLog)
    if user_id:
        base = base.filter(NetworkLog.user_id == user_id)
    total = base.count()
    anomalies = base.filter(NetworkLog.is_anomaly == True).count()
    critical = base.filter(NetworkLog.severity == "critical").count()
    high = base.filter(NetworkLog.severity == "high").count()
    medium = base.filter(NetworkLog.severity == "medium").count()
    low = base.filter(NetworkLog.severity == "low").count()
    return {
        "total_flows": total,
        "total_anomalies": anomalies,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
    }

@router.get("/logs/network/by-device")
def get_network_activity_by_device(user_id: Optional[str] = None, db: Session = Depends(get_db)):
    from sqlalchemy import func
    query = db.query(
        NetworkLog.dst_ip,
        func.count(NetworkLog.id).label("total_flows"),
        func.sum(func.cast(NetworkLog.is_anomaly, Integer)).label("anomalies"),
        func.max(NetworkLog.timestamp).label("last_seen"),
        func.avg(NetworkLog.rmse_score).label("avg_rmse"),
    )
    if user_id:
        query = query.filter(NetworkLog.user_id == user_id)
    results = query.group_by(NetworkLog.dst_ip).all()

    return [
        {
            "dst_ip": r.dst_ip,
            "total_flows": r.total_flows,
            "anomalies": int(r.anomalies or 0),
            "last_seen": r.last_seen.isoformat() if r.last_seen else None,
            "avg_rmse": round(float(r.avg_rmse or 0), 6),
        }
        for r in results
    ]
