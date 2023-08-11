import json
from datetime import datetime
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Cookie, WebSocketException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from merchant_app import crud, models, schemas, security
from merchant_app.database import SessionLocal, engine
from merchant_app.schemas import TokenRequest
from merchant_app.ws.manager import ConnectionManager
from shared_dir import conf

import logging


logging.basicConfig(
    level=logging.INFO,
    filename='merchant.log',
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)
models.Base.metadata.create_all(bind=engine)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
manager = ConnectionManager()
app = FastAPI()


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


@app.post("/token/", response_model=schemas.Token)
async def login(form: TokenRequest, db: Session = Depends(get_db)):
    admin_user = crud.get_single_admin_user(db, admin_username=form.username)
    if not admin_user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    if not security.is_password_verified(form.password, admin_user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    logger.debug(f"Admin user {admin_user.username} logged in.")
    return {"access_token": security.create_access_token(admin_user.username), "token_type": "bearer"}


@app.post("/users/", response_model=schemas.User)
async def create_user(user: schemas.UserCreate, db: Session = Depends(get_db),
                      admin_user: models.Admin = Depends(get_admin)):
    db_user = crud.get_user_by_username(db, username=user.username, admin_user_id=admin_user.id)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    logger.debug(f"User {db_user.username} created. {db_user}")
    return crud.create_user(db, user, admin_user_id=admin_user.id)


@app.get("/users/{user_id}", response_model=schemas.User)
async def get_single_user(user_id: int, db: Session = Depends(get_db), admin_user: models.Admin = Depends(get_admin)):
    db_user = crud.get_user(db, user_id=user_id, admin_user_id=admin_user.id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


@app.get("/users/", response_model=list[schemas.User])
async def get_all_users(skip: int = 0, limit: int = 100, is_active: bool | None = None, db: Session = Depends(get_db),
                        admin_user: models.Admin = Depends(get_admin)):
    users = crud.get_users(db, admin_user_id=admin_user.id, skip=skip, limit=limit, is_active=is_active)
    for user in users:
        await refresh_single_user(db, user)
    return users


@app.get("/users/count/", response_model=list[schemas.User])
async def get_all_users(is_active: bool | None = None, db: Session = Depends(get_db),
                        admin_user: models.Admin = Depends(get_admin)):
    users = crud.get_users_count(db, admin_user_id=admin_user.id, is_active=is_active)
    return users


@app.put("/users/{user_id}", response_model=schemas.User)
async def update_single_user(user_id: int, user: schemas.UserUpdate, db: Session = Depends(get_db),
                             admin_user: models.Admin = Depends(get_admin)):
    db_user = crud.get_user(db, user_id, admin_user_id=admin_user.id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    db_user = crud.update_user(db, user_id, user=user, admin_user_id=admin_user.id)
    logger.debug(f"User {db_user.username} updated. {db_user}")
    return db_user


@app.delete("/users/{user_id}", response_model=None)
async def delete_single_user(user_id: int, db: Session = Depends(get_db),
                             admin_user: models.Admin = Depends(get_admin)):
    db_user = crud.get_user(db, user_id, admin_user_id=admin_user.id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    crud.delete_user(db, user_id, admin_user_id=admin_user.id)
    logger.debug(f"User {db_user.username} deleted.")


@app.websocket("/ws/users/")
async def ws(websocket: WebSocket, token: Annotated[str | None, Cookie()] = None, db: Session = Depends(get_db)):
    if token not in conf.slave_tokens:
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION)
    await manager.connect(websocket)
    try:
        while True:
            command = json.loads(await websocket.receive_text())
            logger.info(f"got message {command} from {websocket}")
            db_users = crud.get_all_users(db)
            db_users_info = []
            for user in db_users:
                db_users_info.append({"username": user.username, "password": user.password})
            await manager.send_personal_message({"users": db_users_info}, websocket)

    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.websocket("/ws/add-traffic/")
async def add_traffic(websocket: WebSocket, token: Annotated[str | None, Cookie()] = None, db: Session = Depends(get_db)):
    if token not in conf.slave_tokens:
        logger.warning(f"Unauthorized websocket connection. {websocket}")
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION)
    await manager.connect(websocket)
    logger.info(f"Websocket connection established. {websocket}")
    try:
        while True:
            command = json.loads(await websocket.receive_text())
            username = command["username"]
            size = command["size"]
            db_user = crud.get_user_by_username(db, username=username)
            if db_user is None:
                await manager.send_personal_message({"type": "info", "data": "Wrong user_id/admin"}, websocket)
            crud.update_user_partially(db, username, {"used_traffic": db_user.used_traffic + size})
            await refresh_single_user(db, db_user)

    except WebSocketDisconnect:
        logger.info(f"Websocket connection disconnected. {websocket}")
        manager.disconnect(websocket)


async def refresh_single_user(db: Session, user: schemas.User, broadcast: bool = True):
    if user.max_traffic != 0 and user.used_traffic > user.max_traffic:
        crud.update_user_partially(db, user.id, {"is_active": False})
        logger.info(f"User {user.username} became disabled due to traffic exceed. max traffic: {user.max_traffic}")
        if broadcast:
            await manager.broadcast_disable_user(user.username)

    if user.expire_at != datetime.fromtimestamp(0) and user.expire_at < datetime.now():
        crud.update_user_partially(db, user.id, {"is_active": False})
        logger.info(f"User {user.username} became disabled due to expiration date. expire_at: {user.expire_at}")
        if broadcast:
            await manager.broadcast_disable_user(user.username)
