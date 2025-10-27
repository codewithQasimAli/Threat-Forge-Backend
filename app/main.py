from fastapi import FastAPI
from app.routers import user_router
from app.routers import alert_router
from app.routers.device_router import router as device_router
from app.database import engine
from app.models.user import Base

# Create tables in the database
Base.metadata.create_all(bind=engine)

app = FastAPI()

app.include_router(user_router.router)
app.include_router(device_router) 
app.include_router(alert_router.router)



