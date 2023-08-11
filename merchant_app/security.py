from datetime import datetime, timedelta

from jose import jwt, JWTError
from passlib.context import CryptContext

from shared_dir.conf import ALGORITHM, SECRET_KEY, ACCESS_TOKEN_EXPIRE_DAYS

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def is_password_verified(password, hashed_password):
    return pwd_context.verify(password, hashed_password)


def hash_password(password):
    return pwd_context.hash(password)


def create_access_token(username: str, expires_delta: timedelta | None = None):

    to_encode = {
        "sub": username,
    }

    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None
