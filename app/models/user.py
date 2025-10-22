# auth_api/app/models/user.py
from sqlalchemy import String, DateTime, func, Boolean, Integer # noqa
from sqlalchemy.orm import Mapped, mapped_column
from datetime import datetime
from typing import Optional

from app.db.base import Base

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[Optional[str]] = mapped_column(String(150))
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False) # Inicia inativo
    # --- Novos Campos ---
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    verification_token_hash: Mapped[Optional[str]] = mapped_column(String(255), index=True) # Hash do token
    verification_token_expires: Mapped[Optional[datetime]] = mapped_column(DateTime)
    # --- Fim Novos Campos ---
    reset_password_token_hash: Mapped[Optional[str]] = mapped_column(String(255), index=True)
    reset_password_token_expires: Mapped[Optional[datetime]] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), onupdate=func.now())