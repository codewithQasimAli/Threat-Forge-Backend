---
name: threatforge-backend
description: ThreatForge backend conventions. Use when editing any Python file, creating routes, or debugging API issues.
---

# ThreatForge Backend Conventions

## Tech Stack
- FastAPI (not Flask), PostgreSQL via NeonDB, Kitsune IDS
- All models in app/models/, routers in app/routers/, services in app/services/

## Rules
- NEVER use pip install, always use python -m pip install --break-system-packages
- Device router has NO prefix - routes are /device, /devices/user/{id}, /devices/all
- Alert router prefix is /alerts - routes are /alerts/alerts, /alerts/alerts/user/{id}
- Logs router prefix is /logs - routes are /logs/network, /logs/network/stats
- user_id in network_logs is VARCHAR not INT
- Always filter by user_id for multi-user data isolation
- Kitsune threshold is 0.000007, trained on CICIDS2017 Monday data
- datetime.utcnow() is deprecated, use datetime.now(datetime.UTC)

## Common Mistakes to Avoid
- Don't assume device route has /devices prefix
- Don't count acknowledged alerts in severity breakdowns
- Always set user_id on network_logs (lookup from devices table by dst_ip)
- NeonDB SSL times out after inactivity - restart uvicorn to fix
