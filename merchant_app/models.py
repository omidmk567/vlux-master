from sqlalchemy import Column, ForeignKey, Integer, String, DateTime, Boolean
from sqlalchemy.orm import relationship

from .database import Base


class Admin(Base):
    __tablename__ = "admins"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    created_at = Column(DateTime)

    users = relationship("User", back_populates="creator")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime)
    max_traffic = Column(Integer)
    used_traffic = Column(Integer, default=0)
    expire_at = Column(DateTime)
    contact = Column(String)
    creator_id = Column(Integer, ForeignKey("admins.id"))

    creator = relationship("Admin", back_populates="users")
