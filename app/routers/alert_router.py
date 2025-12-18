from fastapi import APIRouter, Depends, HTTPException
from app.services.alert_service import AlertService
from app.database import get_db
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from app.models.alert import Alert

router = APIRouter()


class AlertCreate(BaseModel):
    user_id: int
    device_id: Optional[int] = None
    title: str
    message: str
    severity: str
    status: Optional[str] = "active"
    acknowledged: Optional[bool] = False


class AlertUpdate(BaseModel):
    title: Optional[str] = None
    message: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    acknowledged: Optional[bool] = None


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
        # Update the db session for each request while keeping the same instance
        _alert_service_instance.db = db
    
    return _alert_service_instance


@router.post("/kitsune/initialize")
def initialize_kitsune(alert_service: AlertService = Depends(get_alert_service)):
    """Initialize the Kitsune IDS system"""
    success = alert_service.initialize_kitsune()
    if success:
        return {
            "status": "initialized",
            "message": "Kitsune IDS initialized successfully"
        }
    else:
        raise HTTPException(
            status_code=500,
            detail="Failed to initialize Kitsune IDS"
        )


@router.get("/kitsune/statistics")
def get_kitsune_statistics(alert_service: AlertService = Depends(get_alert_service)):
    """Get Kitsune IDS statistics"""
    stats = alert_service.get_kitsune_statistics()
    if stats is not None:
        return stats
    else:
        raise HTTPException(
            status_code=503,
            detail="Kitsune IDS not initialized"
        )


@router.post("/kitsune/process-packet")
def process_network_packet(
    packet: PacketData,
    alert_service: AlertService = Depends(get_alert_service)
):
    """Process a network packet through Kitsune IDS"""
    try:
        packet_dict = {
            'timestamp': packet.timestamp,
            'source_ip': packet.source_ip,
            'dest_ip': packet.dest_ip,
            'source_port': packet.source_port,
            'dest_port': packet.dest_port,
            'protocol': packet.protocol,
            'length': packet.length
        }
        
        alert = alert_service.process_network_packet(
            packet_dict,
            packet.user_id,
            packet.device_id
        )
        
        if alert:
            return {
                "status": "processed",
                "anomaly_detected": True,
                "alert_created": True,
                "alert": {
                    "id": alert.id,
                    "title": alert.title,
                    "severity": alert.severity,
                    "source_ip": alert.source_ip,
                    "dest_ip": alert.dest_ip,
                    "rmse_score": alert.rmse_score
                }
            }
        else:
            # Get the last RMSE score if available
            stats = alert_service.get_kitsune_statistics()
            rmse = stats.get('last_rmse_score', 0) if stats else 0
            
            return {
                "status": "processed",
                "anomaly_detected": False,
                "alert_created": False,
                "rmse_score": rmse
            }
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"Error processing packet: {str(e)}"
        )


@router.get("/alerts", response_model=list[AlertResponse])
def get_alerts_route(
    skip: int = 0, 
    limit: int = 100,
    acknowledged: Optional[bool] = None,
    db: Session = Depends(get_db)
):
    """Get all alerts with optional filtering"""
    query = db.query(Alert)
    
    if acknowledged is not None:
        query = query.filter(Alert.acknowledged == acknowledged)
    
    alerts = query.offset(skip).limit(limit).all()
    return alerts


@router.get("/alerts/user/{user_id}", response_model=list[AlertResponse])
def get_alerts_by_user_route(
    user_id: int,
    skip: int = 0,
    limit: int = 100,
    acknowledged: Optional[bool] = None,
    db: Session = Depends(get_db)
):
    """Get alerts for a specific user with optional filtering"""
    query = db.query(Alert).filter(Alert.user_id == user_id)
    
    if acknowledged is not None:
        query = query.filter(Alert.acknowledged == acknowledged)
    
    alerts = query.offset(skip).limit(limit).all()
    return alerts


@router.get("/alerts/device/{device_id}", response_model=list[AlertResponse])
def get_alerts_by_device_route(
    device_id: int,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """Get alerts for a specific device"""
    alerts = db.query(Alert).filter(
        Alert.device_id == device_id
    ).offset(skip).limit(limit).all()
    return alerts


@router.get("/alerts/{id}", response_model=AlertResponse)
def get_alert_by_id(id: int, db: Session = Depends(get_db)):
    """Get a specific alert by ID"""
    alert = db.query(Alert).filter(Alert.id == id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.post("/alerts", response_model=AlertResponse, status_code=201)
def create_alert_route(alert: AlertCreate, db: Session = Depends(get_db)):
    """Create a new alert manually"""
    from app.services.alert_service import create_alert
    
    db_alert = create_alert(
        db=db,
        user_id=alert.user_id,
        device_id=alert.device_id,
        title=alert.title,
        message=alert.message,
        severity=alert.severity,
        status=alert.status,
        acknowledged=alert.acknowledged
    )
    return db_alert


@router.put("/alerts/{id}", response_model=AlertResponse)
def update_alert_route(id: int, alert: AlertUpdate, db: Session = Depends(get_db)):
    """Update an existing alert"""
    from app.services.alert_service import update_alert_by_id
    
    db_alert = update_alert_by_id(
        db=db,
        id=id,
        **alert.dict(exclude_unset=True)
    )
    if db_alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return db_alert


@router.put("/alerts/{id}/acknowledge", response_model=AlertResponse)
def acknowledge_alert_route(id: int, db: Session = Depends(get_db)):
    """Acknowledge an alert"""
    alert = db.query(Alert).filter(Alert.id == id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    alert.acknowledged = True
    alert.acknowledged_at = datetime.now()
    db.commit()
    db.refresh(alert)
    
    return alert


@router.delete("/alerts/{id}")
def delete_alert_route(id: int, db: Session = Depends(get_db)):
    """Delete an alert"""
    alert = db.query(Alert).filter(Alert.id == id).first()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    db.delete(alert)
    db.commit()
    
    return {
        "message": "Alert deleted successfully",
        "id": id
    }