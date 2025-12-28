"""
WebSocket Router for Alerts
============================

Add this file: app/routers/websocket_router.py
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from app.websockets.alert_websocket import alert_ws_manager

router = APIRouter()


@router.websocket("/ws/alerts")
async def websocket_alerts_endpoint(
    websocket: WebSocket,
    user_id: int = Query(..., description="User ID for authentication")
):
    """
    WebSocket endpoint for real-time alerts.
    
    Usage:
        ws://localhost:8000/ws/alerts?user_id=1
    
    Messages sent to client:
        {
            "type": "new_alert",
            "data": {
                "id": 123,
                "title": "Network anomaly detected",
                "message": "...",
                "severity": "high",
                ...
            }
        }
    """
    await alert_ws_manager.connect(websocket, user_id)
    
    try:
        # Keep connection alive and handle incoming messages
        while True:
            # Wait for any message from client (heartbeat/ping)
            data = await websocket.receive_text()
            
            # Echo back or handle client messages if needed
            if data == "ping":
                await websocket.send_text("pong")
    
    except WebSocketDisconnect:
        alert_ws_manager.disconnect(websocket, user_id)
        print(f"Client disconnected: user_id={user_id}")
    
    except Exception as e:
        print(f"WebSocket error for user {user_id}: {e}")
        alert_ws_manager.disconnect(websocket, user_id)