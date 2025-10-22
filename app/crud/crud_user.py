# auth_api/app/crud/crud_user.py
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import Optional, Dict, Any # Importar Dict, Any
import hashlib
import secrets
from app.crud.base import CRUDBase
from app.models.user import User
from datetime import datetime, timedelta, timezone # Importar datetime, timedelta, timezone
from app.schemas.user import UserCreate, UserUpdate
from app.core.security import get_password_hash, verify_password, create_password_reset_token
# --- Importar CRUD do refresh token ---
from app.crud import crud_refresh_token
from app.core.config import settings # Importar settings
# --- Fim import ---
from loguru import logger # Adicionar logger
# --- Importar exceção customizada ---
from app.core.exceptions import AccountLockedException 
from sqlalchemy.orm.attributes import flag_modified # Importar para merge de JSON


class CRUDUser(CRUDBase[User, UserCreate, UserUpdate]):
    async def get_by_email(self, db: AsyncSession, *, email: str) -> Optional[User]:
        stmt = select(User).filter(User.email == email)
        result = await db.execute(stmt)
        return result.scalars().first()

    # Sobrescreve o create para hashear a senha
    async def create(self, db: AsyncSession, *, obj_in: UserCreate) -> tuple[User, str]: # Retorna usuário e token
        # ... (lógica de create) ...
        verification_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(verification_token.encode('utf-8')).hexdigest()
        expires_delta = timedelta(minutes=settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_MINUTES)
        expires_at = datetime.now(timezone.utc) + expires_delta

        db_obj = User(
            email=obj_in.email,
            hashed_password=get_password_hash(obj_in.password),
            full_name=obj_in.full_name,
            is_active=False,
            is_verified=False,
            verification_token_hash=token_hash,
            verification_token_expires=expires_at.replace(tzinfo=None),
            custom_claims={} # CORREÇÃO: Inicia custom_claims como um dict vazio
        )
        db.add(db_obj)
        await db.commit()
        await db.refresh(db_obj)
        return db_obj, verification_token

    async def verify_user_email(self, db: AsyncSession, *, token: str) -> User | None:
        """Verifica um usuário usando o token e o ativa."""
        # ... (lógica de verify_user_email permanece igual) ...
        token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
        now = datetime.now(timezone.utc).replace(tzinfo=None) # UTC naive

        stmt = select(User).where(
            User.verification_token_hash == token_hash,
            User.verification_token_expires > now,
            User.is_verified == False
        )
        result = await db.execute(stmt)
        user = result.scalars().first()

        if user:
            user.is_active = True
            user.is_verified = True
            user.verification_token_hash = None
            user.verification_token_expires = None
            db.add(user)
            await db.commit()
            await db.refresh(user)
            return user
        return None

    # --- LÓGICA DE AUTENTICAÇÃO (EXISTENTE) ---
    async def authenticate(
        self, db: AsyncSession, *, email: str, password: str
    ) -> Optional[User]:
        
        user = await self.get_by_email(db, email=email)
        if not user:
            return None
            
        now = datetime.now(timezone.utc).replace(tzinfo=None) # UTC naive

        # --- 1. VERIFICAR SE A CONTA ESTÁ BLOQUEADA (permanece igual) ---
        if user.locked_until and user.locked_until > now:
            logger.warning(f"Tentativa de login para conta bloqueada: {email}")
            raise AccountLockedException(
                f"Account locked until {user.locked_until}",
                locked_until=user.locked_until
            )
            
        # --- 2. VERIFICAR SENHA (MOVIDO PARA CIMA) ---
        if not verify_password(password, user.hashed_password):
            # --- LÓGICA DE FALHA: Incrementar contador e bloquear se necessário ---
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= settings.LOGIN_MAX_FAILED_ATTEMPTS:
                lock_duration = timedelta(minutes=settings.LOGIN_LOCKOUT_MINUTES)
                user.locked_until = now + lock_duration
                # Reinicia o contador após bloquear
                user.failed_login_attempts = 0 
                logger.warning(f"CONTA BLOQUEADA: {email} bloqueada por {lock_duration} devido a tentativas falhas.")
            
            db.add(user)
            await db.commit()
            return None # Senha incorreta
            
        # --- 3. VERIFICAR SE ESTÁ ATIVO E VERIFICADO (MOVIDO PARA BAIXO) ---
        if not user.is_active or not user.is_verified:
            logger.warning(f"Tentativa de login (senha correta) falhou para email não ativo/verificado: {email}")
            return None 
        
        # --- 4. SUCESSO: Resetar contador de falhas ---
        if user.failed_login_attempts > 0 or user.locked_until:
            user.failed_login_attempts = 0
            user.locked_until = None
            db.add(user)
            await db.commit() # Commit do reset
            
        return user
    # --- FIM DA LÓGICA DE AUTENTICAÇÃO ---

    # --- NOVO MÉTODO PARA CUSTOM_CLAIMS ---
    async def update_custom_claims(
        self, db: AsyncSession, *, user: User, claims: Dict[str, Any]
    ) -> User:
        """
        Mescla (patch) os claims customizados do usuário.
        Novos valores nos 'claims' de entrada sobrescrevem os antigos.
        """
        if user.custom_claims:
            # Mescla os dicionários
            user.custom_claims.update(claims)
            # Sinaliza ao SQLAlchemy que o campo JSONB foi modificado
            flag_modified(user, "custom_claims")
        else:
            user.custom_claims = claims
        
        db.add(user)
        await db.commit()
        await db.refresh(user)
        return user
    # --- FIM NOVO MÉTODO ---

    async def generate_password_reset_token(
            self, db: AsyncSession, *, user: User
        ) -> tuple[User, str]:
        """
        Gera um token JWT, calcula seu hash e data de expiração,
        e salva no usuário. Retorna o usuário e o token original.
        """
        # ... (lógica de generate_password_reset_token permanece igual) ...
        token, expires_at = create_password_reset_token(email=user.email)
        token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
        
        user.reset_password_token_hash = token_hash
        user.reset_password_token_expires = expires_at
        
        db.add(user)
        await db.commit()
        await db.refresh(user)
        
        return user, token

    async def get_user_by_reset_token(
            self, db: AsyncSession, *, token: str
        ) -> User | None:
        """Busca um usuário ativo pelo hash do token de reset."""
        # ... (lógica de get_user_by_reset_token permanece igual) ...
        token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
        now = datetime.now(timezone.utc).replace(tzinfo=None)

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
        """Atualiza a senha do usuário, invalida o token de reset E LIMPA O BLOQUEIO."""
        # ... (lógica de reset_password permanece igual) ...
        
        user.hashed_password = get_password_hash(new_password)
        user.reset_password_token_hash = None
        user.reset_password_token_expires = None
        
        # Limpa o lockout (EXISTENTE)
        user.failed_login_attempts = 0
        user.locked_until = None
        user.is_active = True
        
        db.add(user)
        
        revoked_count = await crud_refresh_token.revoke_all_refresh_tokens_for_user(
            db, user_id=user.id
        )
        logger.info(f"Revogados {revoked_count} refresh tokens para usuário ID {user.id} após reset de senha.")
        
        await db.commit()
        await db.refresh(user)
        return user


user = CRUDUser(User)