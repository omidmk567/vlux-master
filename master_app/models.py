import uuid

from sqlalchemy import Column, ForeignKey, Integer, String, DateTime, Boolean
from sqlalchemy.orm import relationship

from .database import Base


def generate_uuid():
    return str(uuid.uuid4())


class Admin(Base):
    __tablename__ = "admins"

    id = Column(String, primary_key=True, index=True, default=generate_uuid)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    created_at = Column(DateTime)

    users = relationship("User", back_populates="creator")


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, index=True, default=generate_uuid)
    username = Column(String, unique=True, index=True)
    password = Column(String)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime)
    max_traffic = Column(Integer)
    upload = Column(Integer, default=0)
    download = Column(Integer, default=0)
    expire_at = Column(DateTime)
    contact = Column(String)
    creator_id = Column(String, ForeignKey("admins.id"))

    creator = relationship("Admin", back_populates="users")
