# auth_api/app/core/security.py
from datetime import datetime, timedelta, timezone
from typing import Any, Dict
from passlib.context import CryptContext
from jose import jwt, JWTError
from .config import settings # Keep importing settings
import secrets

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# REMOVE the top-level constants that read from settings immediately
# ACCESS_ALGORITHM = settings.ALGORITHM
# ACCESS_SECRET_KEY = settings.SECRET_KEY
# ACCESS_TOKEN_EXPIRE_MINUTES = settings.ACCESS_TOKEN_EXPIRE_MINUTES
# REFRESH_ALGORITHM = settings.ALGORITHM
# REFRESH_SECRET_KEY = settings.REFRESH_SECRET_KEY
# REFRESH_TOKEN_EXPIRE_DAYS = settings.REFRESH_TOKEN_EXPIRE_DAYS
# RESET_SECRET_KEY = settings.RESET_PASSWORD_SECRET_KEY or settings.SECRET_KEY
# RESET_ALGORITHM = settings.ALGORITHM
# RESET_TOKEN_EXPIRE_MINUTES = settings.RESET_PASSWORD_TOKEN_EXPIRE_MINUTES


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        password_bytes = plain_password.encode('utf-8')[:72]
        return pwd_context.verify(password_bytes, hashed_password)
    except Exception:
        return False

def get_password_hash(password: str) -> str:
    password_bytes = password.encode('utf-8')[:72]
    return pwd_context.hash(password_bytes)

# --- Funções para Access Token ---
def create_access_token(data: Dict[str, Any]) -> str:
    to_encode = data.copy()
    # Access settings inside the function
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "token_type": "access"})
    # Access settings inside the function
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str) -> Dict | None:
    try:
        # Access settings inside the function
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            options={"verify_aud": False}
        )
        return payload
    except JWTError:
        return None

# --- Funções para Refresh Token ---
def create_refresh_token(data: Dict[str, Any]) -> tuple[str, datetime]:
    to_encode = data.copy()
    # Access settings inside the function
    expires_delta = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire, "token_type": "refresh"})
    # Access settings inside the function
    encoded_jwt = jwt.encode(to_encode, settings.REFRESH_SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt, expire.replace(tzinfo=None)

def decode_refresh_token(token: str) -> Dict | None:
    try:
        # Access settings inside the function
        payload = jwt.decode(
            token,
            settings.REFRESH_SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            options={"verify_aud": False}
        )
        if payload.get("token_type") != "refresh":
             return None
        return payload
    except JWTError:
        return None

# --- Funções para Reset Token ---
def create_password_reset_token(email: str) -> tuple[str, datetime]:
    # Access settings inside the function
    reset_secret = settings.RESET_PASSWORD_SECRET_KEY or settings.SECRET_KEY
    expires_delta = timedelta(minutes=settings.RESET_PASSWORD_TOKEN_EXPIRE_MINUTES)
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode = {
        "exp": expire,
        "nbf": datetime.now(timezone.utc),
        "sub": email,
        "token_type": "password_reset"
    }
    # Access settings inside the function
    encoded_jwt = jwt.encode(to_encode, reset_secret, algorithm=settings.ALGORITHM)
    return encoded_jwt, expire.replace(tzinfo=None)

def decode_password_reset_token(token: str) -> Dict | None:
    try:
        # Access settings inside the function
        reset_secret = settings.RESET_PASSWORD_SECRET_KEY or settings.SECRET_KEY
        payload = jwt.decode(
            token,
            reset_secret,
            algorithms=[settings.ALGORITHM],
            options={"verify_aud": False}
        )
        if payload.get("token_type") != "password_reset" or "sub" not in payload:
             return None
        return payload
    except JWTError:
        return None