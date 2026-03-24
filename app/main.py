from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware  
from app.database import engine, Base
from app.models.simulation import SimulationRun
from app.models.network_log import NetworkLog
from app.models.notification_preference import NotificationPreference

# Import models FIRST
from app.models.user import User
from app.models. alert import Alert
from app.models.device import Device

from app. routers import user_router
from app.routers import alert_router, websocket_router
from app.routers import simulation_router
from app.routers import network_log_router
from app.routers import notification_router
from app.routers import export_router
from app.routers.device_router import router as device_router

# Create all tables
Base.metadata. create_all(bind=engine)

app = FastAPI(title="ThreatForge API", version="1.0.0")

# (CORS Configuration)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins (for development/exam)
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)

# Register routers with proper prefix
app. include_router(user_router. router, tags=["authentication"])
app.include_router(alert_router. router, prefix="/alerts", tags=["alerts"])
app.include_router(device_router, tags=["devices"])
app.include_router(websocket_router.router, tags=["websockets"])
app.include_router(simulation_router.router, tags=["simulation"])
app.include_router(network_log_router.router, tags=["network-logs"])
app.include_router(notification_router.router, tags=["notifications"])
app.include_router(export_router.router, tags=["export"])

# Root endpoint (optional - for testing)
@app.get("/")
def read_root():
    return {"message": "ThreatForge API is running", "status": "ok", "version": "1.0.0"}