import json
import logging
from datetime import datetime
from typing import Annotated

import requests
from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Cookie, WebSocketException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from master_app import crud, models, schemas, security
from master_app.database import SessionLocal, engine
from master_app.schemas import TokenRequest
from master_app.ws.manager import ConnectionManager
from shared_dir import conf

logging.basicConfig(
    level=logging.INFO,
    filename='master.log',
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

origins = [
    "*",
]

logger = logging.getLogger(__name__)
models.Base.metadata.create_all(bind=engine)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
ws_manager = ConnectionManager()
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


for db_session in get_db():
    for admin in conf.admins:
        crud.create_admin_user(db_session, schemas.AdminCreate(**admin))


async def get_admin(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    if not token:
        raise HTTPException(status_code=401, detail="Unauthorized")
    username = security.decode_access_token(token)
    if username is None:
        raise HTTPException(status_code=400, detail="Invalid Access Token")
    user = crud.get_single_admin_user(db, username)
    return user


@app.post("/api/token/", response_model=schemas.Token)
async def login(form: TokenRequest, db: Session = Depends(get_db)):
    admin_user = crud.get_single_admin_user(db, admin_username=form.username)
    if not admin_user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    if not security.is_password_verified(form.password, admin_user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    logger.debug(f"Admin user {admin_user.username} logged in.")
    return {"access_token": security.create_access_token(admin_user.username), "token_type": "bearer"}


@app.post("/api/users/", response_model=schemas.User)
async def create_user(user: schemas.UserCreate, db: Session = Depends(get_db),
                      admin_user: models.Admin = Depends(get_admin)):
    db_user = crud.get_user_by_username(db, username=user.username, admin_user_id=admin_user.id)
    if db_user:
        raise HTTPException(status_code=400, detail=f"Username {db_user.username} already registered")
    created_user = crud.create_user(db, user, admin_user_id=admin_user.id)
    logger.debug(f"User {created_user.username} created. {created_user}")
    await ws_manager.broadcast_add_user(created_user.username, created_user.password)
    return created_user


@app.get("/api/users/count/", response_model=int)
async def get_users_count(is_active: bool | None = None, db: Session = Depends(get_db),
                          admin_user: models.Admin = Depends(get_admin)):
    users_count = crud.get_users_count(db, admin_user_id=admin_user.id, is_active=is_active)
    return users_count


@app.get("/api/users/{user_id}/", response_model=schemas.User)
async def get_single_user(user_id: str, db: Session = Depends(get_db), admin_user: models.Admin = Depends(get_admin)):
    db_user = crud.get_user(db, user_id=user_id, admin_user_id=admin_user.id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


@app.get("/api/users/", response_model=list[schemas.User])
async def get_all_users(skip: int = 0, limit: int = 100, is_active: bool | None = None, q: str | None = None,
                        db: Session = Depends(get_db), admin_user: models.Admin = Depends(get_admin)):
    users = crud.get_users(db, admin_user_id=admin_user.id, skip=skip, limit=limit, is_active=is_active, q=q)
    for user in users:
        await refresh_single_user(db, user)
    return users


@app.put("/api/users/{user_id}/", response_model=schemas.User)
async def update_single_user(user_id: str, user: schemas.UserUpdate, db: Session = Depends(get_db),
                             admin_user: models.Admin = Depends(get_admin)):
    db_user = crud.get_user(db, user_id, admin_user_id=admin_user.id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    old_is_active = db_user.is_active
    old_password = db_user.password
    updated_user = crud.update_user(db, user_id, user=user, admin_user_id=admin_user.id)
    # Check for is_active change
    if old_is_active != updated_user.is_active:
        if updated_user.is_active:
            logger.debug(f"User {updated_user.username} enabled.")
            await ws_manager.broadcast_enable_user(updated_user.username)
        else:
            logger.debug(f"User {updated_user.username} disabled.")
            await ws_manager.broadcast_disable_user(updated_user.username)
    # Check for password change
    if old_password != updated_user.password:
        logger.debug(f"Password of user {updated_user.username} changed to {updated_user.password}.")
        await ws_manager.broadcast_change_password(updated_user.username, updated_user.password)
    logger.debug(f"User {updated_user.username} updated. {updated_user}")
    return updated_user


@app.delete("/api/users/{user_id}/", response_model=None)
async def delete_single_user(user_id: str, db: Session = Depends(get_db),
                             admin_user: models.Admin = Depends(get_admin)):
    db_user = crud.get_user(db, user_id, admin_user_id=admin_user.id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    crud.delete_user(db, user_id, admin_user_id=admin_user.id)
    await ws_manager.broadcast_delete_user(db_user.username)
    logger.debug(f"User {db_user.username} deleted.")


@app.post("/ws/auth/", response_model=schemas.Token)
async def get_ws_token(request: Request):
    client_ip = request.client.host
    logger.info(f"Client ip {client_ip} has requested to connect")
    response = requests.get('https://api.runonflux.io/apps/location/vlux').json()
    data = response["data"]
    token = conf.slave_token if client_ip in [x['ip'].split(':')[0] for x in data] else ""
    return {"access_token": token, "token_type": "str"}


@app.websocket("/ws/")
async def ws(websocket: WebSocket, session: Annotated[str | None, Cookie()] = None, db: Session = Depends(get_db)):
    if session != conf.slave_token:
        logger.warning(f"Unauthorized websocket connection. {websocket}")
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION)
    await ws_manager.connect(websocket)
    logger.info(f"Websocket connection established. {websocket}")
    try:
        while True:
            command = json.loads(await websocket.receive_text())
            logger.info(f"got message {command} from {websocket}")
            command_type = command["type"]

            if command_type == "fetch-users":
                users = process_fetch_users(db)
                await ws_manager.send_personal_all_users(users, websocket)

            elif command_type == "add-traffic":
                command_data = command["data"]
                for cm in command_data:
                    updated_user = process_add_traffic(db, cm)
                    if updated_user is None:
                        logger.warning(f"Adding traffic to not existing user. {cm}")
                        return
                    await refresh_single_user(db, updated_user)

            elif command_type == "error":
                logger.error(f"Error occurred on connection {websocket}. {command}")
                # Todo: handle errors
                pass
    except WebSocketDisconnect:
        logger.info(f"Websocket connection disconnected. {websocket}")
        ws_manager.disconnect(websocket)


def process_fetch_users(db: Session):
    db_users = crud.get_all_users(db, is_active=True)
    db_users_info = []
    for user in db_users:
        db_users_info.append({"username": user.username, "password": user.password})
    return db_users_info


def process_add_traffic(db: Session, data: dict):
    username = data["username"]
    download = data["download"]
    upload = data["upload"]
    db_user = crud.get_user_by_username(db, username=username)
    if db_user is None:
        return None
    return crud.update_user_partially(db, db_user.id, {
        "download": db_user.download + download,
        "upload": db_user.upload + upload
    })


async def refresh_single_user(db: Session, user: schemas.User, broadcast: bool = True):
    if user.max_traffic != 0 and (user.download + user.upload) >= user.max_traffic:
        crud.update_user_partially(db, user.id, {"is_active": False})
        logger.info(f"User {user.username} became disabled due to traffic exceed. max traffic: {user.max_traffic}")
        if broadcast:
            await ws_manager.broadcast_disable_user(user.username)
        return

    if user.expire_at != datetime.fromtimestamp(0) and user.expire_at < datetime.now():
        crud.update_user_partially(db, user.id, {"is_active": False})
        logger.info(f"User {user.username} became disabled due to expiration date. expire_at: {user.expire_at}")
        if broadcast:
            await ws_manager.broadcast_disable_user(user.username)
