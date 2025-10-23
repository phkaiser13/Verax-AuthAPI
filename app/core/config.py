# auth_api/app/core/config.py
import os
import logging
from pydantic_settings import BaseSettings
from pydantic import EmailStr
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
ENV_FILE_PATH = BASE_DIR / ".env"

class Settings(BaseSettings):
    
    # Core
    DATABASE_URL: str
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Refresh Token
    REFRESH_SECRET_KEY: str
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # --- Configurações de Email (SendGrid) ---
    SENDGRID_API_KEY: str
    EMAIL_FROM: EmailStr
    EMAIL_FROM_NAME: str | None = "Verax AuthAPI"
    # --- Fim SendGrid ---
    
    # --- Configurações SMTP (Removidas) ---
    # ... (removidas) ...
    # --- Fim SMTP ---
    
    # Email Links
    VERIFICATION_URL_BASE: str = "http://localhost:8000/verify"
    EMAIL_VERIFICATION_TOKEN_EXPIRE_MINUTES: int = 60
    
    # Password Reset
    RESET_PASSWORD_SECRET_KEY: str | None = None
    RESET_PASSWORD_TOKEN_EXPIRE_MINUTES: int = 30
    RESET_PASSWORD_URL_BASE: str = "http://localhost:8000/reset-password"

    # Account Lockout
    LOGIN_MAX_FAILED_ATTEMPTS: int = 5
    LOGIN_LOCKOUT_MINUTES: int = 15

    # Chave de API Interna
    INTERNAL_API_KEY: str

    # --- NOVAS Configurações OIDC JWT Claims ---
    JWT_ISSUER: str = "urn:verax:authapi" # Default se não estiver no .env
    JWT_AUDIENCE: str = "urn:verax:client" # Default se não estiver no .env
    # --- FIM NOVAS ---

    class Config:
        case_sensitive = True
        env_file = ENV_FILE_PATH
        env_file_encoding = 'utf-8'

try:
    settings = Settings()
except Exception as e:
    logging.error(f"FATAL: Erro ao carregar 'settings' a partir do .env em {ENV_FILE_PATH}: {e}")
    raise e