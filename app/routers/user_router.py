from fastapi import APIRouter, Depends, HTTPException, status
from app.services.user_service import (
    create_user,
    get_user_by_email,
    verify_password,
    generate_otp,
    validate_otp,
    cache_pending_user,
)
from app.database import get_db
from sqlalchemy.orm import Session
from pydantic import BaseModel
from app.core.security import create_access_token
from app.core.email import send_email
import os
from dotenv import load_dotenv

load_dotenv()

router = APIRouter()

class UserSignup(BaseModel):
    name: str
    email: str
    password: str

class UserSignin(BaseModel):
    email: str
    password: str

class OTPVerify(BaseModel):
    email: str
    otp: str

@router.post("/signup")
def signup(user: UserSignup, db: Session = Depends(get_db)):
    existing_user = get_user_by_email(db, user.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    # Cache pending user (hashed password) and send OTP
    cache_pending_user(user.name, user.email, user.password)
    otp = generate_otp(user.email)
    try:
        send_email(
            to_email=user.email,
            subject="Your ThreatForge verification code",
            body=f"Hi {user.name},\n\nYour verification code is: {otp}\nThis code expires in 5 minutes.\n\nIf you didn't request this, ignore this email.",
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to send OTP email; please try again later.")

    return {"message": "OTP sent to your email. Please verify to complete signup."}

@router.post("/signin")
def signin(user: UserSignin, db: Session = Depends(get_db)):
    db_user = get_user_by_email(db, user.email)
    if not db_user or not verify_password(user.password, db_user.password):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    # Generate access token
    access_token = create_access_token(data={"sub": user.email})
    # Update last login
    from datetime import datetime, timezone
    try:
        db_user.lastlogin = datetime.now(timezone.utc)
        db.add(db_user)
        db.commit()
    except Exception:
        db.rollback()
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/verify-otp")
def verify_otp(payload: OTPVerify, db: Session = Depends(get_db)):
    ok = validate_otp(db, payload.email, payload.otp)
    if not ok:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")
    return {"message": "OTP verified successfully"}
