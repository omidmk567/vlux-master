from sqlalchemy.orm import Session

from . import models, schemas, security


def create_user(db: Session, user: schemas.UserCreate, admin_user_id: str):
    db_user = models.User(**user.dict(), creator_id=admin_user_id)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def create_admin_user(db: Session, admin_user: schemas.AdminCreate):
    existing_admin = get_single_admin_user(db, admin_username=admin_user.username)
    if existing_admin:
        existing_admin.hashed_password = security.hash_password(admin_user.password)
        return existing_admin

    db_user = models.Admin(username=admin_user.username, hashed_password=security.hash_password(admin_user.password),
                           created_at=admin_user.created_at)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def get_single_admin_user(db: Session, admin_username: str):
    return db.query(models.Admin).filter(models.Admin.username == admin_username).first()


def get_admin_users(db: Session):
    return db.query(models.Admin).all()


def get_user(db: Session, user_id: str, admin_user_id: str | None = None):
    if admin_user_id is None:
        return db.query(models.User).filter(models.User.id == user_id).first()
    return db.query(models.User).filter(models.User.id == user_id).filter(
        models.User.creator_id == admin_user_id).first()


def get_user_by_username(db: Session, username: str, admin_user_id: str | None = None):
    if admin_user_id is None:
        return db.query(models.User).filter(models.User.username == username).first()
    return db.query(models.User).filter(models.User.username == username).filter(
        models.User.creator_id == admin_user_id).first()


def get_users(db: Session, admin_user_id: str, skip: int, limit: int, is_active: bool | None = None):
    if is_active is None:
        return db.query(models.User).filter(models.User.creator_id == admin_user_id).offset(skip).limit(limit).all()

    return db.query(models.User).filter(models.User.creator_id == admin_user_id).filter(
        models.User.is_active == is_active).offset(skip).limit(limit).all()


def get_all_users(db: Session):
    return db.query(models.User).all()


def get_users_count(db: Session, admin_user_id: str | None, is_active: bool | None = None):
    if admin_user_id is None:
        if is_active is None:
            return db.query(models.User).count()
        return db.query(models.User).filter(models.User.is_active == is_active).count()
    if is_active is None:
        return db.query(models.User).filter(models.User.creator_id == admin_user_id).count()
    return db.query(models.User).filter(models.User.creator_id == admin_user_id).filter(
        models.User.is_active == is_active).count()


def update_user(db: Session, user_id: str, user: schemas.UserUpdate, admin_user_id: str):
    db_user = get_user(db, user_id, admin_user_id)
    for attr, value in user.dict().items():
        setattr(db_user, attr, value)

    db.commit()
    db.refresh(db_user)
    return db_user


def update_user_partially(db: Session, user_id: str, update: dict, admin_user_id: str | None = None):
    db_user = get_user(db, user_id, admin_user_id)
    for attr, value in update.items():
        setattr(db_user, attr, value)

    db.commit()
    db.refresh(db_user)
    return db_user


def delete_user(db: Session, user_id: str, admin_user_id: str):
    db.query(models.User).filter(models.User.id == user_id).filter(models.User.creator_id == admin_user_id).delete()
    db.commit()
