from fastapi import APIRouter, Depends, HTTPException, status
from app.services.user_service import (
    create_user,
    get_user_by_email,
    verify_password,
    generate_otp,
    validate_otp,
    cache_pending_user,
    delete_user_by_email,
    update_user_by_email,
    generate_reset_otp,
    verify_reset_otp,
    can_reset_password,
    clear_reset_state,
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
    phone: str | None = None

class UserSignin(BaseModel):
    email: str
    password: str

class OTPVerify(BaseModel):
    email: str
    otp: str

class UserUpdate(BaseModel):
    name: str | None = None
    password: str | None = None
    phone: str | None = None

class ForgotPasswordRequest(BaseModel):
    email: str

class ForgotPasswordVerify(BaseModel):
    email: str
    otp: str

class ForgotPasswordReset(BaseModel):
    email: str
    new_password: str

@router.post("/signup")
def signup(user: UserSignup, db: Session = Depends(get_db)):
    existing_user = get_user_by_email(db, user.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    # Cache pending user (hashed password) and send OTP
    cache_pending_user(
        user.name,
        user.email,
        user.password,
        phone=user.phone,
    )
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
    user_payload = {
        "id": db_user.id,
        "name": db_user.name,
        "email": db_user.email,
        "phone": getattr(db_user, "phone", None),
        "createdAt": getattr(db_user, "createdAt", None),
        "lastlogin": getattr(db_user, "lastlogin", None),
    }
    return {"access_token": access_token, "token_type": "bearer", "user": user_payload}


@router.post("/verify-otp")
def verify_otp(payload: OTPVerify, db: Session = Depends(get_db)):
    ok = validate_otp(db, payload.email, payload.otp)
    if not ok:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")
    return {"message": "OTP verified successfully"}


@router.delete("/user/{email}")
def delete_user(email: str, db: Session = Depends(get_db)):
    deleted = delete_user_by_email(db, email)
    if not deleted:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": "User deleted"}


@router.put("/user/{email}")
def edit_user(email: str, payload: UserUpdate, db: Session = Depends(get_db)):
    user = update_user_by_email(
        db,
        email,
        name=payload.name,
        password=payload.password,
        phone=payload.phone,
    )
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "message": "User updated",
        "email": user.email,
        "name": user.name,
        "phone": user.phone,
    }


# ===== Forgot Password (OTP) =====

@router.post("/forgot-password")
def forgot_password(payload: ForgotPasswordRequest, db: Session = Depends(get_db)):
    # Do not reveal user existence
    user = get_user_by_email(db, payload.email)
    if user:
        otp = generate_reset_otp(payload.email)
        try:
            send_email(
                to_email=payload.email,
                subject="Your ThreatForge password reset code",
                body=f"We received a request to reset your password.\n\nYour code is: {otp}\nThis code expires in 15 minutes.\n\nIf you didn't request this, you can ignore this email.",
            )
        except Exception:
            # Intentionally still return generic message
            pass
    return {"message": "If the email exists, we have sent reset instructions."}


@router.post("/forgot-password/verify")
def forgot_password_verify(payload: ForgotPasswordVerify):
    ok = verify_reset_otp(payload.email, payload.otp)
    if not ok:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")
    return {"message": "OTP verified. You may now reset your password."}


@router.post("/forgot-password/reset")
def forgot_password_reset(payload: ForgotPasswordReset, db: Session = Depends(get_db)):
    # if not can_reset_password(payload.email):
    #     raise HTTPException(status_code=400, detail="Reset not authorized or expired. Verify OTP again.")
    user = update_user_by_email(db, payload.email, password=payload.new_password)
    if not user:
        # Clear state anyway to avoid keeping tokens
        clear_reset_state(payload.email)
        # Generic response to avoid user enumeration; still use 400 for client flow
        raise HTTPException(status_code=400, detail="Reset failed. Verify OTP again.")
    # Clear state after successful reset
    clear_reset_state(payload.email)
    return {"message": "Password has been reset successfully."}
