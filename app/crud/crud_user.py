# auth_api/app/crud/crud_user.py
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import Optional
import hashlib
import secrets
from app.crud.base import CRUDBase
from app.models.user import User
from datetime import datetime, timedelta, timezone
from app.schemas.user import UserCreate, UserUpdate
from app.core.security import get_password_hash, verify_password, create_password_reset_token
# --- Importar CRUD do refresh token ---
from app.crud import crud_refresh_token
from app.core.config import settings
# --- Fim import ---
from loguru import logger # Adicionar logger

class CRUDUser(CRUDBase[User, UserCreate, UserUpdate]):
    async def get_by_email(self, db: AsyncSession, *, email: str) -> Optional[User]:
        stmt = select(User).filter(User.email == email)
        result = await db.execute(stmt)
        return result.scalars().first()

    # Sobrescreve o create para hashear a senha
    async def create(self, db: AsyncSession, *, obj_in: UserCreate) -> tuple[User, str]: # Retorna usuário e token
        # Gerar token de verificação seguro
        verification_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(verification_token.encode('utf-8')).hexdigest()
        expires_delta = timedelta(minutes=settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_MINUTES)
        expires_at = datetime.now(timezone.utc) + expires_delta

        db_obj = User(
            email=obj_in.email,
            hashed_password=get_password_hash(obj_in.password),
            full_name=obj_in.full_name,
            is_active=False, # Inicia inativo
            is_verified=False, # Inicia não verificado
            verification_token_hash=token_hash,
            verification_token_expires=expires_at.replace(tzinfo=None) # Armazena UTC naive
        )
        db.add(db_obj)
        await db.commit()
        await db.refresh(db_obj)
        # Retorna o usuário e o token original (não o hash) para envio do email
        return db_obj, verification_token

    async def verify_user_email(self, db: AsyncSession, *, token: str) -> User | None:
        """Verifica um usuário usando o token e o ativa."""
        token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
        now = datetime.now(timezone.utc).replace(tzinfo=None) # UTC naive

        stmt = select(User).where(
            User.verification_token_hash == token_hash,
            User.verification_token_expires > now,
            User.is_verified == False # Só verifica se ainda não foi verificado
        )
        result = await db.execute(stmt)
        user = result.scalars().first()

        if user:
            user.is_active = True
            user.is_verified = True
            user.verification_token_hash = None # Invalida o token
            user.verification_token_expires = None
            db.add(user)
            await db.commit()
            await db.refresh(user)
            return user
        return None

    # Modificar authenticate para checar is_verified
    async def authenticate(
        self, db: AsyncSession, *, email: str, password: str
    ) -> Optional[User]:
        user = await self.get_by_email(db, email=email)
        if not user:
            return None
        # --- VERIFICAR SE ESTÁ ATIVO E VERIFICADO ---
        if not user.is_active or not user.is_verified:
            # Poderia retornar um erro específico para email não verificado
            logger.warning(f"Tentativa de login falhou para email não ativo/verificado: {email}")
            return None # Ou levantar HTTPException com status customizado
        # --- FIM VERIFICAÇÃO ---
        if not verify_password(password, user.hashed_password):
            return None
        return user

async def generate_password_reset_token(
        self, db: AsyncSession, *, user: User
    ) -> tuple[User, str]:
        """
        Gera um token JWT, calcula seu hash e data de expiração,
        e salva no usuário. Retorna o usuário e o token original.
        """
        token, expires_at = create_password_reset_token(email=user.email)
        token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
        
        user.reset_password_token_hash = token_hash
        user.reset_password_token_expires = expires_at # Já está em UTC naive
        
        db.add(user)
        await db.commit()
        await db.refresh(user)
        
        return user, token # Retorna o token original para envio do email

async def get_user_by_reset_token(
        self, db: AsyncSession, *, token: str
    ) -> User | None:
        """Busca um usuário ativo pelo hash do token de reset."""
        token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
        now = datetime.now(timezone.utc).replace(tzinfo=None) # UTC naive

        stmt = select(User).where(
            User.reset_password_token_hash == token_hash,
            User.reset_password_token_expires > now,
            User.is_active == True
        )
        result = await db.execute(stmt)
        return result.scalars().first()

async def reset_password(
        self, db: AsyncSession, *, user: User, new_password: str
    ) -> User:
        """Atualiza a senha do usuário e invalida o token de reset."""
        
        # Define a nova senha
        user.hashed_password = get_password_hash(new_password)
        
        # Invalida o token de reset
        user.reset_password_token_hash = None
        user.reset_password_token_expires = None
        
        db.add(user)
        
        # Revoga todos os refresh tokens ativos por segurança
        revoked_count = await crud_refresh_token.revoke_all_refresh_tokens_for_user(
            db, user_id=user.id
        )
        logger.info(f"Revogados {revoked_count} refresh tokens para usuário ID {user.id} após reset de senha.")
        
        await db.commit()
        await db.refresh(user)
        return user


user = CRUDUser(User)