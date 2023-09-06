from fastapi import WebSocket
from starlette.websockets import WebSocketState


class ConnectionManager:
    def __init__(self):
        self.active_connections: set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def send_personal_message(self, command: dict, websocket: WebSocket):
        try:
            if websocket.client_state == WebSocketState.CONNECTED and websocket.application_state == WebSocketState.CONNECTED:
                await websocket.send_json(command)
            else:
                print(websocket.client_state, websocket.application_state)
        except RuntimeError as err:
            print(f"Could not send message to client {websocket.client.host}. {err}")


    async def broadcast(self, command: dict):
        for connection in self.active_connections:
            await self.send_personal_message(command, connection)

    async def send_personal_error(self, error: str, websocket: WebSocket):
        command = {
            "type": "error",
            "data": {
                "description": error
            }
        }
        await self.send_personal_message(command, websocket)

    async def send_personal_all_users(self, users: list, websocket: WebSocket):
        command = {
            "type": "fetch-users",
            "data": {
                "users": users
            }
        }
        await self.send_personal_message(command, websocket)

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

    async def broadcast_add_user(self, username: str, password: str):
        command = {
            "type": "add-user",
            "data": {
                "username": username,
                "password": password,
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

    async def broadcast_change_password(self, username: str, new_password: str):
        command = {
            "type": "change-password",
            "data": {
                "username": username,
                "new-password": new_password,
            }
        }
        await self.broadcast(command)
