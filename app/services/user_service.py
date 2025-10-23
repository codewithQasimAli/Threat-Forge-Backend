from app.models.user import User
from app.database import SessionLocal
from sqlalchemy.orm import Session
import bcrypt
from fastapi import HTTPException, status
import random
import redis
import os
import json
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

# Connect to Redis for OTP
redis_client = redis.StrictRedis(host=os.getenv("REDIS_HOST", 'localhost'),
                                 port=int(os.getenv("REDIS_PORT", '6379')),
                                 db=int(os.getenv("REDIS_DB", '0')),
                                 decode_responses=True)

# TTL for OTP and pending user cache (seconds)
OTP_TTL_SECONDS = int(os.getenv("OTP_TTL_SECONDS", "300"))

def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

def create_user(db: Session, name: str, email: str, password: str, *, hashed_password: Optional[str] = None):
    if hashed_password is None:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    else:
        # assume already hashed string passed in
        hashed_password = hashed_password
    db_user = User(name=name, email=email, password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def verify_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def generate_otp(email: str) -> str:
    otp = str(random.randint(100000, 999999))
    redis_client.setex(f"otp:{email}", OTP_TTL_SECONDS, otp)
    return otp


def cache_pending_user(name: str, email: str, password: str) -> None:
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    data = {"name": name, "email": email, "password": hashed}
    redis_client.setex(f"pending_user:{email}", OTP_TTL_SECONDS, json.dumps(data))


def validate_otp(db: Session, email: str, otp: str) -> bool:
    stored = redis_client.get(f"otp:{email}")
    if not stored or stored != otp:
        return False
    # fetch pending user payload
    raw = redis_client.get(f"pending_user:{email}")
    if not raw:
        return False
    try:
        payload = json.loads(raw)
    except Exception:
        return False
    # create user in DB with hashed password from cache
    create_user(db, payload["name"], payload["email"], password="", hashed_password=payload["password"])
    # cleanup keys
    redis_client.delete(f"otp:{email}")
    redis_client.delete(f"pending_user:{email}")
    return True
