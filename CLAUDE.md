# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

**Activate virtual environment (Windows):**
```
.\venv\Scripts\Activate
```

**Run development server:**
```
uvicorn app.main:app --reload
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

**Run CICIDS2017 dataset loader (IDS training/detection):**
```
python app/services/cicids_loader.py --interactive
python app/services/cicids_loader.py --mode train --file datasets/CICIDS2017/preprocessed/Monday-WorkingHours.pcap_ISCX_preprocessed.csv --max-rows 50000
python app/services/cicids_loader.py --mode detect --file datasets/CICIDS2017/preprocessed/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX_preprocessed.csv
```

**Install dependencies:**
```
pip install -r requirements.txt
```

## Architecture

ThreatForge is a network intrusion detection system (NIDS) backend built with FastAPI. It integrates the Kitsune IDS (ensemble of autoencoders via KitNET) to detect network anomalies in real time, then pushes alerts to connected clients over WebSocket.

### External services required
- **PostgreSQL** (NeonDB cloud): connection string via `DB_URL` env var. SQLAlchemy creates all tables on startup via `Base.metadata.create_all`.
- **Redis** (local on port 6379): used exclusively for OTP storage and pending-user cache during signup/password-reset flows.
- **SMTP** (Gmail): for sending OTP verification emails during signup and password reset.

### Required `.env` variables
```
DB_URL, SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES,
SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM,
REDIS_HOST, REDIS_PORT, REDIS_DB
```

### Request flow

1. **Auth** (`app/routers/user_router.py`): Signup is a two-step flow — user data is cached in Redis with a hashed password, OTP sent by email, then `POST /verify-otp` commits the user to the DB. Signin returns a JWT. Password reset uses a separate Redis-backed OTP with a 15-minute TTL.

2. **Device management** (`app/routers/device_router.py`): CRUD for network devices. MAC addresses are normalized to uppercase colon-separated format on write. Duplicate IP/MAC per user is rejected at the router level.

3. **Alert system** (`app/routers/alert_router.py` + `app/services/alert_service.py`): Alerts are created either manually via `POST /alerts/alerts` or automatically by Kitsune IDS on packet anomaly detection. Every alert mutation (create, update, acknowledge, delete) pushes a WebSocket event to the owning user.

4. **Kitsune IDS** (`app/services/kitsune_service.py`): Wraps the external `Kitsune-py` library located at `services/Kitsune-py/` (not tracked in git). Must be cloned separately. `KitsuneIDSService` is instantiated lazily via `AlertService.initialize_kitsune()`. Training has two phases: feature mapping (first 100 packets by default) then anomaly-detection training (up to 1000 packets). After training, the threshold is set adaptively as `mean + 3*std` of training RMSE scores. Severity is determined by how many multiples of the threshold the RMSE exceeds.

5. **WebSocket** (`app/websockets/alert_websocket.py`, `app/routers/websocket_router.py`): Single global `AlertWebSocketManager` instance (`alert_ws_manager`). Clients connect to `ws://host/ws/alerts?user_id=<id>`. Supports multiple concurrent connections per user. Ping/pong keepalive is handled by echoing `"pong"` on `"ping"` messages.

6. **CICIDS2017 loader** (`app/services/cicids_loader.py`): Standalone script for offline IDS training/evaluation using the CICIDS2017 dataset (stored in `datasets/CICIDS2017/`, not tracked in git). Trains KitNET on Monday BENIGN traffic and detects anomalies on attack traffic files. Can push alerts to the running API.

### Key design decisions
- `AlertService` is a **singleton** in `alert_router.py` (global `_alert_service_instance`) so that KitNET training state persists across HTTP requests.
- Pydantic schemas (request/response models) are defined inline in each router file, not in a separate schemas directory.
- `app/main.py` imports all models before calling `create_all` to ensure SQLAlchemy sees all table definitions.
- Trained Kitsune models are serialized as `.pkl` files in the `models/` directory.
