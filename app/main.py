from fastapi import FastAPI
from app.database import engine, Base

# Import models FIRST
from app.models.user import User
from app.models.alert import Alert
from app.models.device import Device

from app.routers import user_router
from app.routers import alert_router, websocket_router  
from app.routers.device_router import router as device_router

# Create all tables
Base.metadata.create_all(bind=engine)

app = FastAPI()

# Register routers with proper prefix
app.include_router(user_router.router)
app.include_router(alert_router.router, prefix="/alerts", tags=["alerts"])  # ← Add prefix here
app.include_router(device_router)
app.include_router(websocket_router.router, tags=["websockets"])