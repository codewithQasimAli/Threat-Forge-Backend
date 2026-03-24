from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.notification_preference import NotificationPreference
from pydantic import BaseModel

router = APIRouter()

class NotificationPrefRequest(BaseModel):
    user_id: str
    push_enabled: bool = True
    sound_enabled: bool = True
    vibration_enabled: bool = True

@router.post("/notifications/preferences")
def save_notification_preferences(req: NotificationPrefRequest, db: Session = Depends(get_db)):
    existing = db.query(NotificationPreference).filter(
        NotificationPreference.user_id == req.user_id
    ).first()
    if existing:
        existing.push_enabled = req.push_enabled
        existing.sound_enabled = req.sound_enabled
        existing.vibration_enabled = req.vibration_enabled
    else:
        pref = NotificationPreference(
            user_id=req.user_id,
            push_enabled=req.push_enabled,
            sound_enabled=req.sound_enabled,
            vibration_enabled=req.vibration_enabled,
        )
        db.add(pref)
    db.commit()
    return {"message": "Notification preferences saved successfully"}

@router.get("/notifications/preferences/{user_id}")
def get_notification_preferences(user_id: str, db: Session = Depends(get_db)):
    pref = db.query(NotificationPreference).filter(
        NotificationPreference.user_id == user_id
    ).first()
    if not pref:
        return {"push_enabled": True, "sound_enabled": True, "vibration_enabled": True}
    return {
        "push_enabled": pref.push_enabled,
        "sound_enabled": pref.sound_enabled,
        "vibration_enabled": pref.vibration_enabled,
    }
