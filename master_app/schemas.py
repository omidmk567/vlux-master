import random
import string
from datetime import datetime

from pydantic import BaseModel, Field


class UserBase(BaseModel):
    username: str
    password: str
    is_active: bool
    max_traffic: int
    expire_at: datetime
    contact: str


class UserCreate(UserBase):
    username: str = Field(default_factory=lambda: ''.join(random.choices(string.ascii_lowercase + string.digits, k=7)))
    password: str = Field(default_factory=lambda: ''.join(random.choices(string.ascii_letters + string.digits, k=8)))
    is_active: bool = True
    max_traffic: int = 0
    expire_at: datetime = datetime.fromtimestamp(0)
    contact: str = ""
    download: int = 0
    upload: int = 0
    created_at: datetime = datetime.now()


class User(UserBase):
    id: str
    creator_id: str
    download: int
    upload: int
    created_at: datetime

    class Config:
        orm_mode = True


class UsersCount(BaseModel):
    count: int


class UserUpdate(UserBase):
    pass


class AdminBase(BaseModel):
    username: str


class AdminCreate(AdminBase):
    password: str
    created_at: datetime = datetime.now()


class Admin(AdminBase):
    id: str
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
