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

## FYP2 Progress

### Completed
- `app/services/cicids_loader.py` — threshold fix applied, now always loads from pkl automatically, never asks user to type threshold
- `app/services/pcap_to_features.py` — NEW file created, reads PCAP files and extracts 52 CICIDS2017 features in exact same order as `cicids_loader.py` `feature_columns`, uses scapy, groups packets into bidirectional flows, outputs list of dicts with `features`/`src_ip`/`dst_ip`/`src_port`/`dst_port`/`protocol`/`flow_duration`/`packet_count`/`start_time`

### GNS3 Topology — COMPLETE AND VERIFIED
- GNS3 project: **ThreatForge**, local server mode, port 3080
- **Home-Router**: Ethernet switch connecting all nodes
- **SmartCamera**: VPCS, IP `192.168.56.10`, connected to Home-Router Ethernet0
- **SmartThermostat**: VPCS, IP `192.168.56.20`, connected to Home-Router Ethernet1
- **SmartLock**: VPCS, IP `192.168.56.30`, connected to Home-Router Ethernet2
- **Cloud1**: VMnet8 bridge, connected to Home-Router Ethernet3
- **Kali Linux VM**: VMware NAT (VMnet8), IP `192.168.56.128`, hping3 + nmap installed
- Packet capture: right-click cable → Start capture → auto-saves to `C:\Users\USER\GNS3\projects\ThreatForge\project-files\captures\`
- PCAP save path for `run_simulation.py`: `simulation/captures/` inside backend folder
- `pcap_to_features.py` tested on real GNS3 traffic: extracted 1 flow, shape `(52,)` — VERIFIED

### Next Files to Build (in order)
1. `app/services/run_simulation.py` — full orchestrator (see spec below)
2. `app/services/gns3_client.py` — wrapper for GNS3 REST API calls (start/stop nodes, get PCAP path)
3. `app/routers/simulation_router.py` — routes: `GET /simulation/history`, `GET /simulation/latest`
4. `app/routers/network_log_router.py` — routes: `GET /logs` with filters
5. `app/models/simulation_model.py` — DB table for simulation run history
6. `app/models/network_log_model.py` — DB table for per-flow network logs
7. `SimulationScreen.js` (frontend) — results dashboard, sim history, live alert feed
8. `NetworkLogsScreen.js` (frontend) — table of IP/protocol/timestamp/RMSE per flow

### Next: run_simulation.py Spec
- **Location**: `app/services/run_simulation.py`
- **Purpose**: Full orchestrator — controls GNS3 via REST API, triggers attacks via SSH to Kali, captures PCAP, calls `pcap_to_features.py`, feeds Kitsune, creates alerts
- **GNS3 REST API base URL**: `http://localhost:3080/v2`
- **Kali SSH**: `192.168.56.128`, user: `kali`, password: `kali`
- **Attack 1 — DDoS**: `hping3 -S --flood -V -p 80 192.168.56.10` (30 seconds)
- **Attack 2 — PortScan**: `nmap -sS 192.168.56.10 192.168.56.20 192.168.56.30`
- **PCAP output folder**: `C:/Users/USER/GNS3/projects/ThreatForge/project-files/captures/`
- After capture: call `pcap_to_features.extract_features_from_pcap(pcap_path)`
- Then: load Kitsune model from `models/kitsune_latest.pkl`
- Then: for each flow, apply normalization, run `kitsune.process()`, check RMSE vs threshold
- Then: if RMSE > threshold, call `alert_service` to create alert
- Save simulation run to `SimulationRun` DB model (to be created)
- **Kitsune model path**: `models/kitsune_latest.pkl` (already trained and saved)

### Architecture
- **Approach B**: backend script runs simulation (not user-triggered from app)
- `run_simulation.py` runs from terminal, feeds pipeline, alerts go to DB via `alert_service.py`
- `SimulationScreen.js` is a results dashboard only, not a control panel
- `cicids_loader.py` kept as demo/fallback tool, NOT part of the GNS3 pipeline
