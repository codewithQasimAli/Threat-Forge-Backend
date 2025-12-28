"""
WebSocket Manager for Real-Time Alerts
======================================

Add this file: app/websockets/alert_websocket.py
"""

from fastapi import WebSocket, WebSocketDisconnect
from typing import Dict, Set
import json
import asyncio


class AlertWebSocketManager:
    """
    Manages WebSocket connections for real-time alert notifications.
    One connection per user_id.
    """
    
    def __init__(self):
        # Store active connections: {user_id: Set of WebSocket connections}
        self.active_connections: Dict[int, Set[WebSocket]] = {}
    
    async def connect(self, websocket: WebSocket, user_id: int):
        """Accept WebSocket connection and register it for user"""
        await websocket.accept()
        
        if user_id not in self.active_connections:
            self.active_connections[user_id] = set()
        
        self.active_connections[user_id].add(websocket)
        print(f"WebSocket connected for user {user_id}. Total connections: {len(self.active_connections[user_id])}")
    
    def disconnect(self, websocket: WebSocket, user_id: int):
        """Remove WebSocket connection"""
        if user_id in self.active_connections:
            self.active_connections[user_id].discard(websocket)
            
            # Clean up empty sets
            if not self.active_connections[user_id]:
                del self.active_connections[user_id]
            
            print(f"WebSocket disconnected for user {user_id}")
    
    async def send_alert_to_user(self, user_id: int, alert_data: dict):
        """
        Send alert to specific user's WebSocket connections.
        Called when new alert is created in database.
        """
        if user_id not in self.active_connections:
            print(f"No active WebSocket connections for user {user_id}")
            return
        
        # Prepare message
        message = json.dumps({
            "type": "new_alert",
            "data": alert_data
        })
        
        # Send to all connections for this user
        disconnected = set()
        for connection in self.active_connections[user_id]:
            try:
                await connection.send_text(message)
            except Exception as e:
                print(f"Error sending to WebSocket: {e}")
                disconnected.add(connection)
        
        # Clean up failed connections
        for connection in disconnected:
            self.disconnect(connection, user_id)
    
    async def broadcast_to_all(self, alert_data: dict):
        """Send alert to all connected users (optional)"""
        message = json.dumps({
            "type": "new_alert",
            "data": alert_data
        })
        
        for user_id, connections in list(self.active_connections.items()):
            for connection in list(connections):
                try:
                    await connection.send_text(message)
                except Exception:
                    self.disconnect(connection, user_id)
    
    def get_active_user_count(self) -> int:
        """Get number of users with active connections"""
        return len(self.active_connections)
    
    def get_total_connections(self) -> int:
        """Get total number of WebSocket connections"""
        return sum(len(connections) for connections in self.active_connections.values())


# Global WebSocket manager instance
alert_ws_manager = AlertWebSocketManager()