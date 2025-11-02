from fastapi import APIRouter, Depends, HTTPException
from app.services.alert_service import (
    create_alert,
    get_alerts,
    get_alerts_by_user_id,
    get_alerts_by_device_id,
    update_alert_by_id,
    delete_alert_by_id,
)
from app.database import get_db
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from app.models.alert import Alert  # Ensure the path to Alert is correct


router = APIRouter()

# Pydantic models for data validation
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
    created_at: datetime

    class Config:
        from_attributes = True


# Create Alert
@router.post("/alert", response_model=AlertResponse)
def create_alert_route(alert: AlertCreate, db: Session = Depends(get_db)):
    db_alert = create_alert(
        db=db,
        user_id=alert.user_id,
        device_id=alert.device_id,
        title=alert.title,
        message=alert.message,
        severity=alert.severity,
        status=alert.status,
        acknowledged=alert.acknowledged if alert.acknowledged is not None else False,
    )
    return db_alert


# Get All Alerts
@router.get("/alerts", response_model=list[AlertResponse])
def get_alerts_route(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    alerts = get_alerts(db=db, skip=skip, limit=limit)
    return alerts


# Get Alerts by User ID
@router.get("/alerts/user/{user_id}", response_model=list[AlertResponse])
def get_alerts_by_user_route(user_id: int, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    alerts = get_alerts_by_user_id(db=db, user_id=user_id, skip=skip, limit=limit)
    return alerts


# Get Alerts by Device ID
@router.get("/alerts/device/{device_id}", response_model=list[AlertResponse])
def get_alerts_by_device_route(device_id: int, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    alerts = get_alerts_by_device_id(db=db, device_id=device_id, skip=skip, limit=limit)
    return alerts


# Update Alert by ID
@router.put("/alerts/{id}", response_model=AlertResponse)
def update_device_route(id: int, alert: AlertUpdate, db: Session = Depends(get_db)):
    db_alert = update_alert_by_id(db=db, id=id, **alert.dict(exclude_unset=True))
    if db_alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return db_alert



# Delete Alert by ID
@router.delete("/alerts/{id}", response_model=AlertResponse)
def delete_alert_route(id: int, db: Session = Depends(get_db)):
    # Find the alert in the database
    db_alert = db.query(Alert).filter(Alert.id == id).first()

    if db_alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Delete the alert
    db.delete(db_alert)
    db.commit()

    # Return the deleted alert details (you can adjust the data returned based on your needs)
    return {
        "id": db_alert.id,
        "user_id": db_alert.user_id,
        "title": db_alert.title,
        "message": db_alert.message,
        "severity": db_alert.severity,
        "status": db_alert.status,
        "acknowledged": db_alert.acknowledged,
        "created_at": db_alert.created_at
    }


