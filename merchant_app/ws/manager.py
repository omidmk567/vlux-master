from fastapi import WebSocket


class ConnectionManager:
    def __init__(self):
        self.active_connections: set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def send_personal_message(self, command: dict, websocket: WebSocket):
        await websocket.send_json(command)

    async def broadcast(self, command: dict):
        for connection in self.active_connections:
            await self.send_personal_message(command, connection)

    async def broadcast_disable_user(self, username: str):
        command = {
            "type": "disable-user",
            "data": {
                "username": username,
            }
        }
        await self.broadcast(command)

    async def broadcast_enable_user(self, username: str):
        command = {
            "type": "enable-user",
            "data": {
                "username": username,
            }
        }
        await self.broadcast(command)

    async def broadcast_add_user(self, username: str):
        command = {
            "type": "add-user",
            "data": {
                "username": username,
            }
        }
        await self.broadcast(command)

    async def broadcast_delete_user(self, username: str):
        command = {
            "type": "delete-user",
            "data": {
                "username": username,
            }
        }
        await self.broadcast(command)
