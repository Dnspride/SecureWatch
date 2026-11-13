"""
WebSocket Manager for live SOC dashboard pushes and security alerts.
"""
from __future__ import annotations

import asyncio
from typing import Dict, List, Set
from uuid import UUID

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import structlog

log = structlog.get_logger(__name__)

ws_router = APIRouter(tags=["WebSockets"])


class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.add(websocket)
        log.info("WebSocket client connected", total_clients=len(self.active_connections))

    def disconnect(self, websocket: WebSocket) -> None:
        self.active_connections.discard(websocket)
        log.info("WebSocket client disconnected", total_clients=len(self.active_connections))

    async def broadcast_json(self, data: dict) -> None:
        """Broadcast event to all connected dashboard sessions."""
        disconnected = []
        for connection in list(self.active_connections):
            try:
                await connection.send_json(data)
            except Exception:
                disconnected.append(connection)

        for conn in disconnected:
            self.disconnect(conn)


manager = ConnectionManager()


@ws_router.websocket("/ws/dashboard")
async def websocket_dashboard(websocket: WebSocket) -> None:
    """Live dashboard WebSocket push."""
    await manager.connect(websocket)
    try:
        while True:
            # Keep-alive heartbeat & client message consumption
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        log.warning("WebSocket error", error=str(e))
        manager.disconnect(websocket)
