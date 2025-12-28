"""
Alert Router (Updated with WebSocket push)
=========================================
File: app/routers/alert_router.py

- Sends real-time WebSocket message to the user when a new alert is created
- Also sends update messages on acknowledge / update / delete (optional but implemented)
"""

from fastapi import APIRouter, Depends, HTTPException
from app.services.alert_service import AlertService
from app.database import get_db
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
from app.models.alert import Alert

from app.websockets.alert_websocket import alert_ws_manager

router = APIRouter()


# ============================================================================
# SCHEMAS
# ============================================================================

class AlertCreate(BaseModel):
    user_id: int
    device_id: Optional[int] = None
    title: str
    message: str
    severity: str
    status: Optional[str] = "active"
    acknowledged: Optional[bool] = False

    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    rmse_score: Optional[float] = None
    details: Optional[str] = None


class AlertUpdate(BaseModel):
    title: Optional[str] = None
    message: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    acknowledged: Optional[bool] = None

    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    rmse_score: Optional[float] = None
    details: Optional[str] = None


class AlertResponse(BaseModel):
    id: int
    user_id: int
    device_id: Optional[int] = None
    title: str
    message: str
    severity: str
    status: str
    acknowledged: bool
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    rmse_score: Optional[float] = None
    created_at: datetime
    acknowledged_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class PacketData(BaseModel):
    user_id: int
    device_id: Optional[int] = None
    timestamp: float
    source_ip: str
    dest_ip: str
    source_port: int = 0
    dest_port: int = 0
    protocol: str = "TCP"
    length: int = 0


# ============================================================================
# HELPERS
# ============================================================================

def _alert_to_ws_dict(a: Alert) -> dict:
    """Convert SQLAlchemy Alert -> JSON-serializable dict for WebSocket."""
    return {
        "id": a.id,
        "user_id": a.user_id,
        "device_id": a.device_id,
        "title": a.title,
        "message": a.message,
        "severity": a.severity,
        "status": a.status,
        "acknowledged": a.acknowledged,
        "source_ip": a.source_ip,
        "dest_ip": a.dest_ip,
        "rmse_score": a.rmse_score,
        "details": getattr(a, "details", None),
        "created_at": a.created_at.isoformat() if getattr(a, "created_at", None) else None,
        "acknowledged_at": a.acknowledged_at.isoformat() if getattr(a, "acknowledged_at", None) else None,
    }


async def _push_ws(user_id: int, payload_type: str, data: dict):
    """Send a standard websocket message to user."""
    await alert_ws_manager.send_alert_to_user(
        user_id=user_id,
        alert_data={
            "event": payload_type,   # your frontend can read this
            **data
        }
    )


# ============================================================================
# ALERT SERVICE SINGLETON (your existing approach)
# ============================================================================

_alert_service_instance = None


def get_alert_service(db: Session = Depends(get_db)) -> AlertService:
    """
    Returns a singleton instance of AlertService.
    This ensures Kitsune initialization state persists across requests.
    """
    global _alert_service_instance

    if _alert_service_instance is None:
        _alert_service_instance = AlertService(db)
    else:
        _alert_service_instance.db = db

    return _alert_service_instance


# ============================================================================
# KITSUNE IDS ENDPOINTS
# ============================================================================

@router.post("/kitsune/initialize")
def initialize_kitsune(alert_service: AlertService = Depends(get_alert_service)):
    """Initialize the Kitsune IDS system"""
    success = alert_service.initialize_kitsune()
    if success:
        stats = alert_service.get_kitsune_statistics()
        return {
            "status": "initialized",
            "message": "Kitsune IDS initialized successfully",
            "config": {
                "fm_grace_period": stats["fm_grace_period"],
                "ad_grace_period": stats["ad_grace_period"],
                "initial_threshold": stats["anomaly_threshold"],
            },
        }
    raise HTTPException(status_code=500, detail="Failed to initialize Kitsune IDS. Check server logs.")


@router.get("/kitsune/statistics")
def get_kitsune_statistics(alert_service: AlertService = Depends(get_alert_service)):
    """Get Kitsune IDS statistics and training status"""
    stats = alert_service.get_kitsune_statistics()
    if stats is not None:
        return stats
    raise HTTPException(status_code=503, detail="Kitsune IDS not initialized. Call /kitsune/initialize first.")


@router.post("/kitsune/process-packet")
async def process_network_packet(packet: PacketData, alert_service: AlertService = Depends(get_alert_service)):
    """
    Process a network packet through Kitsune IDS
    Returns detection result and creates alert if anomaly detected
    """
    try:
        packet_dict = {
            "timestamp": packet.timestamp,
            "source_ip": packet.source_ip,
            "dest_ip": packet.dest_ip,
            "source_port": packet.source_port,
            "dest_port": packet.dest_port,
            "protocol": packet.protocol,
            "length": packet.length,
        }

        created_alert = alert_service.process_network_packet(packet_dict, packet.user_id, packet.device_id)
        stats = alert_service.get_kitsune_statistics()

        if created_alert:
            
            await alert_ws_manager.send_alert_to_user(created_alert.user_id, _alert_to_ws_dict(created_alert))

            return {
                "status": "processed",
                "anomaly_detected": True,
                "alert_created": True,
                "alert": {
                    "id": created_alert.id,
                    "title": created_alert.title,
                    "severity": created_alert.severity,
                    "source_ip": created_alert.source_ip,
                    "dest_ip": created_alert.dest_ip,
                    "rmse_score": created_alert.rmse_score,
                },
                "kitsune_stats": {
                    "packet_count": stats["total_packets"],
                    "training_phase": stats["training_phase"],
                    "threshold": stats["anomaly_threshold"],
                    "last_rmse": stats["last_rmse_score"],
                },
            }

        return {
            "status": "processed",
            "anomaly_detected": False,
            "alert_created": False,
            "kitsune_stats": {
                "packet_count": stats["total_packets"],
                "training_phase": stats["training_phase"],
                "progress": stats["progress_percentage"],
                "threshold": stats["anomaly_threshold"],
                "last_rmse": stats["last_rmse_score"],
            },
        }

    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error processing packet: {str(e)}")


# ============================================================================
# ALERT CRUD ENDPOINTS
# ============================================================================

@router.get("/alerts", response_model=List[AlertResponse])
def get_alerts_route(
    skip: int = 0,
    limit: int = 100,
    acknowledged: Optional[bool] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db),
):
    query = db.query(Alert)

    if acknowledged is not None:
        query = query.filter(Alert.acknowledged == acknowledged)

    if severity:
        query = query.filter(Alert.severity == severity)

    return query.order_by(Alert.created_at.desc()).offset(skip).limit(limit).all()


@router.get("/alerts/user/{user_id}", response_model=List[AlertResponse])
def get_alerts_by_user_route(
    user_id: int,
    skip: int = 0,
    limit: int = 100,
    acknowledged: Optional[bool] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db),
):
    query = db.query(Alert).filter(Alert.user_id == user_id)

    if acknowledged is not None:
        query = query.filter(Alert.acknowledged == acknowledged)

    if severity:
        query = query.filter(Alert.severity == severity)

    return query.order_by(Alert.created_at.desc()).offset(skip).limit(limit).all()


@router.get("/alerts/device/{device_id}", response_model=List[AlertResponse])
def get_alerts_by_device_route(device_id: int, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return (
        db.query(Alert)
        .filter(Alert.device_id == device_id)
        .order_by(Alert.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )


@router.get("/alerts/summary/user/{user_id}")
def get_alerts_summary(user_id: int, db: Session = Depends(get_db)):
    total = db.query(Alert).filter(Alert.user_id == user_id).count()
    unacknowledged = db.query(Alert).filter(Alert.user_id == user_id, Alert.acknowledged == False).count()

    def _count_sev(sev: str) -> int:
        return db.query(Alert).filter(Alert.user_id == user_id, Alert.severity == sev).count()

    return {
        "total_alerts": total,
        "unacknowledged": unacknowledged,
        "by_severity": {
            "critical": _count_sev("critical"),
            "high": _count_sev("high"),
            "medium": _count_sev("medium"),
            "low": _count_sev("low"),
        },
    }


@router.get("/alerts/{id}", response_model=AlertResponse)
def get_alert_by_id(id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.post("/alerts", response_model=AlertResponse, status_code=201)
async def create_alert_route(alert: AlertCreate, db: Session = Depends(get_db)):
    from app.services.alert_service import create_alert

    db_alert = create_alert(
        db=db,
        user_id=alert.user_id,
        device_id=alert.device_id,
        title=alert.title,
        message=alert.message,
        severity=alert.severity,
        status=alert.status,
        acknowledged=alert.acknowledged,
        source_ip=alert.source_ip,
        dest_ip=alert.dest_ip,
        rmse_score=alert.rmse_score,
        details=alert.details,
    )

    await alert_ws_manager.send_alert_to_user(db_alert.user_id, _alert_to_ws_dict(db_alert))
    print("Senidng data to postman")
    return db_alert


@router.put("/alerts/{id}", response_model=AlertResponse)
async def update_alert_route(id: int, alert: AlertUpdate, db: Session = Depends(get_db)):
    from app.services.alert_service import update_alert_by_id

    db_alert = update_alert_by_id(db=db, id=id, **alert.dict(exclude_unset=True))
    if db_alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")


    await _push_ws(db_alert.user_id, "alert_updated", {"data": _alert_to_ws_dict(db_alert)})

    return db_alert


@router.put("/alerts/{id}/acknowledge", response_model=AlertResponse)
async def acknowledge_alert_route(id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.acknowledged = True
    alert.acknowledged_at = datetime.now()
    db.commit()
    db.refresh(alert)

    await _push_ws(alert.user_id, "alert_acknowledged", {"data": _alert_to_ws_dict(alert)})

    return alert


@router.delete("/alerts/{id}")
async def delete_alert_route(id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == id).first()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    user_id = alert.user_id
    db.delete(alert)
    db.commit()

    await _push_ws(user_id, "alert_deleted", {"id": id})

    return {"message": "Alert deleted successfully", "id": id}


@router.delete("/alerts/user/{user_id}/all")
async def delete_all_user_alerts(user_id: int, db: Session = Depends(get_db)):
    deleted = db.query(Alert).filter(Alert.user_id == user_id).delete()
    db.commit()


    await _push_ws(user_id, "alerts_deleted_all", {"count": deleted})

    return {"message": f"Deleted {deleted} alerts for user {user_id}", "count": deleted}
