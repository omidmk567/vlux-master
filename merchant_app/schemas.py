import random
import string
from datetime import datetime

from pydantic import BaseModel


class UserBase(BaseModel):
    username: str
    password: str
    is_active: bool
    max_traffic: int
    expire_at: datetime
    contact: str


class UserCreate(UserBase):
    username: str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=7))
    password: str = ''.join(random.choices(string.ascii_lowercase + string.ascii_uppercase + string.punctuation, k=10))
    is_active: bool = True
    max_traffic: int = 0
    expire_at: datetime = datetime.fromtimestamp(0)
    contact: str = ""
    used_traffic: int = 0
    created_at: datetime = datetime.now()


class User(UserBase):
    id: int
    creator_id: int
    used_traffic: int
    created_at: datetime

    class Config:
        orm_mode = True


class UserUpdate(UserBase):
    pass


class AdminBase(BaseModel):
    username: str


class AdminCreate(AdminBase):
    password: str
    created_at: datetime = datetime.now()


class Admin(AdminBase):
    id: int
    created_at: datetime
    users: list[UserBase] = []

    class Config:
        orm_mode = True


class TokenRequest(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str
