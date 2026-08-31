# ThreatForge

ThreatForge is a real-time Intrusion Detection System (IDS) for consumer IoT devices. It combines an unsupervised machine-learning detection engine with a cross-platform mobile application to give non-technical smart-home users instant, actionable alerts when their devices are under attack.

The system was validated end-to-end against physical hardware: live DDoS attacks launched from a dedicated attacker host against real TP-Link IP cameras, detected in real time, and pushed to a mobile device as a notification within seconds — whether the app is open, backgrounded, or fully closed.

## Problem Statement

Consumer IoT devices are a well-documented weak point in home networks. They typically lack the compute capacity for on-device security, and existing intrusion detection tools are built for enterprise networks with dedicated security staff — not for a homeowner with a smart camera. The 2016 Mirai botnet, which compromised hundreds of thousands of IoT devices (including IP cameras) to launch some of the largest DDoS attacks on record, is the canonical example of this gap. ThreatForge targets that gap directly: unsupervised anomaly detection that needs no attack signatures, paired with a mobile interface a non-technical user can actually understand.

## Key Features

**Detection**
- Unsupervised anomaly detection using Kitsune's KitNET autoencoder ensemble — no attack signatures required
- Trained on the CICIDS2017 benchmark dataset, validated against both dataset attack traffic and live traffic from physical hardware
- Flow-level feature extraction (52 CICIDS2017-style features per flow) via packet capture and analysis
- Fixed, empirically-derived anomaly threshold — not manually tuned per attack, to keep detection results reproducible and defensible

**Real-time alerting**
- WebSocket channel for instant in-app delivery while the app is open
- Firebase Cloud Messaging for push notifications when the app is backgrounded or fully closed
- Notification delivery verified in all three app states: foreground, background, and killed

**Mobile application**
- Cross-platform React Native app (Android-first)
- Six core modules: Home dashboard, Devices, Alerts, Simulation, Network Logs, Reports
- Device management, alert history with severity filtering, exportable PDF/CSV reports
- JWT-authenticated REST API with per-user data isolation

**Hardware validation**
- Physical testbed with two TP-Link Tapo C200 IP cameras on an isolated network segment
- Dedicated Kali Linux attack host used to generate real DDoS traffic (SYN flood)
- Full pipeline exercised end-to-end: attack traffic → packet capture → feature extraction → model inference → alert creation → mobile push, all on real devices rather than pure simulation

## System Architecture

```
 Mobile App (React Native)
        |
        |  REST + WebSocket
        v
 FastAPI Backend  ------------------------------  Firebase Cloud Messaging
        |                                                    ^
        |  SQLAlchemy ORM                                    | push notifications
        v                                                    |
 PostgreSQL (NeonDB)                                         |
        ^                                                    |
        |  alert records, network logs                       |
        |                                                    |
 Detection Engine (Kitsune / KitNET)  ----------------------- +
        ^
        |  captured traffic, extracted flow features
        |
 Attacker Host (Kali Linux)  ---->  Target IoT Devices (TP-Link Tapo C200)
```

The system is organized into five logical layers:

| Layer | Responsibility |
|---|---|
| Mobile | React Native app — dashboard, device management, alerts, simulation history, logs, reports |
| API | FastAPI — REST endpoints, WebSocket channel, JWT authentication, notification orchestration |
| Detection | Kitsune KitNET — packet capture, flow feature extraction, RMSE-based anomaly scoring |
| Data | PostgreSQL (NeonDB) — users, devices, alerts, and network log persistence |
| Hardware | Physical IoT devices and attacker host on an isolated network segment |

## Technology Stack

| Area | Technology |
|---|---|
| Mobile app | React Native, JavaScript/TypeScript |
| Push notifications | Firebase Cloud Messaging, `@react-native-firebase` |
| Backend API | FastAPI, Python |
| ORM / Database | SQLAlchemy, PostgreSQL (NeonDB) |
| Authentication | JWT |
| Real-time delivery | WebSocket, Firebase Cloud Messaging |
| Detection engine | Kitsune (KitNET autoencoder ensemble) |
| Training / validation dataset | CICIDS2017 |
| Feature extraction | Scapy-based flow analysis |
| Attack simulation | hping3, tcpdump (Kali Linux) |
| IoT hardware | TP-Link Tapo C200 IP cameras |

## Repository Structure

```
.
├── backend/                  # FastAPI application
│   ├── app/
│   │   ├── models/            # SQLAlchemy models (users, devices, alerts, network logs)
│   │   ├── routers/           # REST + WebSocket route handlers
│   │   ├── services/          # Detection pipeline, attack orchestration, business logic
│   │   └── websockets/        # WebSocket connection management
│   ├── models/                 # Trained Kitsune model artifacts
│   ├── run_camera_attack.py    # Entry point for live hardware attack demonstrations
│   └── requirements.txt
│
└── frontend/                  # React Native application
    ├── src/
    │   ├── screens/            # App screens (Home, Devices, Alerts, Simulation, Logs, Reports, Auth)
    │   ├── navigation/         # Tab and stack navigation
    │   └── config/             # API client configuration
    ├── android/                # Android native project and Firebase configuration
    └── App.tsx
```

## Detection Methodology

The detection engine is built on **Kitsune**, an unsupervised network intrusion detection framework published by Mirsky et al. (NDSS 2018). Its core model, **KitNET**, is an ensemble of small autoencoders trained exclusively on benign traffic. Because it never sees attack traffic during training, it does not rely on signatures — it flags any flow that its ensemble cannot reconstruct within a learned error margin.

For each network flow:

1. Traffic is captured at the packet level and grouped into bidirectional flows.
2. A set of statistical features (packet timing, size, and flag distributions, consistent with the CICIDS2017 feature schema) is computed per flow.
3. KitNET produces a reconstruction error (RMSE) for the flow.
4. If the RMSE exceeds a fixed threshold — derived during training as a percentile of the benign RMSE distribution, not tuned per demonstration — the flow is flagged as anomalous and an alert is generated.

Severity is assigned based on attack-type impact rather than raw RMSE magnitude, so that alerts remain operationally meaningful: a denial-of-service condition is classified as Critical, while reconnaissance-style traffic is classified as Medium.

## Notification Delivery

Every alert is delivered through two complementary channels:

- **WebSocket**, for instant delivery into the app UI while it is open in the foreground.
- **Firebase Cloud Messaging**, for system-level push notifications when the app is backgrounded or has been fully terminated.

FCM delivery runs as an asynchronous background task on the API server so that a slow or failed push never blocks alert creation or the WebSocket path, and a short retry policy absorbs transient network failures without any visible delay to the user.

## Getting Started

### Prerequisites

- Python 3.11+
- Node.js 18+ and npm
- PostgreSQL database (a hosted instance such as NeonDB is supported out of the box)
- A Firebase project with Cloud Messaging enabled, for push notification support
- Android Studio / a physical Android device, for running the mobile app

### Backend setup

```bash
cd backend
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux

pip install -r requirements.txt
```

Create a `.env` file in `backend/` (never commit this file):

```
DB_URL=postgresql://<user>:<password>@<host>/<database>?sslmode=require
SECRET_KEY=<a-long-random-secret>
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=<your-email>
SMTP_PASS=<your-app-password>
SMTP_FROM=<your-email>

FIREBASE_CREDENTIALS_PATH=./firebase-admin.json
```

Place your Firebase service-account key at `backend/firebase-admin.json` (not committed to version control).

Run the API:

```bash
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Frontend setup

```bash
cd frontend
npm install
```

Add your Firebase Android configuration file at `android/app/google-services.json`.

```bash
npx react-native run-android
```

## API Overview

| Endpoint | Description |
|---|---|
| `POST /users/signup` / `POST /users/login` | Authentication |
| `GET /devices/user/{userId}` | List a user's registered devices |
| `GET /alerts/alerts/user/{userId}` | Retrieve alert history, filterable by severity, device, and date range |
| `GET /alerts/alerts/summary/user/{userId}` | Aggregate alert counts by severity |
| `GET /logs/network` | Retrieve captured network flow logs |
| `POST /alerts/alerts` | Create an alert (invoked by the detection pipeline) |
| `WS /ws/alerts` | Real-time alert stream for the authenticated user |

## Results

In live testing against physical hardware, the system detected a live DDoS SYN flood attack against a TP-Link Tapo C200 camera with a majority of captured attack-scoped flows correctly classified as anomalous, with all flagged flows correctly attributed to the attacking host. Detection latency from attack launch to mobile notification was on the order of seconds. Detection performance varies with the ambient traffic profile of the target device, which is expected behavior for a statistically-driven anomaly detector rather than a signature match.

## Future Work

- Cloud deployment of the backend and containerization of the detection pipeline
- Additional attack categories (application-layer floods, credential-stuffing patterns)
- Per-device network activity visualizations and drill-down views
- Multi-user role-based access for shared households
- Publication of the detection methodology and hardware validation results

## Team

| Role | Name |
|---|---|
| Developer | Qasim Ali |
| Developer | Muskaan Haleem |
| Supervisor | Dr. Adeel Ansari |

**Institution:** SZABIST University, Karachi — BSCS Final Year Project

## Acknowledgments

The detection engine builds on the open-source **Kitsune** implementation and the **KitNET** algorithm described in Mirsky et al., *"Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection,"* NDSS 2018. Model training and validation used the **CICIDS2017** dataset from the Canadian Institute for Cybersecurity.
