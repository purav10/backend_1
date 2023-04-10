from sqlalchemy.orm import Session
from passlib.context import CryptContext
from fastapi import HTTPException, status
from app import models, schemas
from datetime import datetime, timedelta
import jwt
from app.config import get_settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
settings = get_settings()


def get_password_hash(password):
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def create_customer(db: Session, customer: schemas.CustomerCreate):
    hashed_password = get_password_hash(customer.password)
    db_customer = models.Customer(email=customer.email, hashed_password=hashed_password)
    db.add(db_customer)
    db.commit()
    db.refresh(db_customer)
    return db_customer


def get_customer_by_email(db: Session, email: str):
    return db.query(models.Customer).filter(models.Customer.email == email).first()


def authenticate_customer(db: Session, email: str, password: str):
    customer = get_customer_by_email(db, email)
    if not customer:
        return None
    if not verify_password(password, customer.hashed_password):
        return None
    return customer


def create_access_token(data: dict, expires_delta: int = 24):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=expires_delta)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)
    return encoded_jwt


def get_current_user(db: Session, token: str):
    try:
        decoded_token = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        email = decoded_token.get("sub")
        if email is None:
            return None
    except jwt.JWTError:
        return None
    customer = get_customer_by_email(db, email=email)
    if customer is None:
        return None
    return customer


def get_current_active_user(current_user: models.Customer):
    if not current_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication credentials")
    return current_user
