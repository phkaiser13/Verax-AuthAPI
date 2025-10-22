# auth_api/app/models/user.py
from sqlalchemy import String, DateTime, func, Boolean, Integer # noqa
from sqlalchemy.orm import Mapped, mapped_column
from datetime import datetime
from typing import Optional
from sqlalchemy.dialects.postgresql import JSONB # Importar JSONB

from app.db.base import Base

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[Optional[str]] = mapped_column(String(150))
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False) # Inicia inativo
    # --- Campos Verificação ---
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    verification_token_hash: Mapped[Optional[str]] = mapped_column(String(255), index=True) # Hash do token
    verification_token_expires: Mapped[Optional[datetime]] = mapped_column(DateTime)
    # --- Fim Campos Verificação ---
    reset_password_token_hash: Mapped[Optional[str]] = mapped_column(String(255), index=True)
    reset_password_token_expires: Mapped[Optional[datetime]] = mapped_column(DateTime)
    
    # --- Campos: Account Lockout (EXISTENTES) ---
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True) # Armazena em UTC naive
    # --- Fim Campos Lockout ---

    # --- CORREÇÃO: RENOMEADO DE 'metadata' para 'custom_claims' ---
    custom_claims: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    # --- FIM CORREÇÃO ---
    
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), onupdate=func.now())