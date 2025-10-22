# auth_api/app/api/dependencies.py
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader # Importar APIKeyHeader
from sqlalchemy.ext.asyncio import AsyncSession
from typing import AsyncGenerator
import secrets # Importar secrets para comparação segura

from app.core import security
# --- CORRECTION HERE: Remove AsyncSessionLocal import ---
from app.db.session import get_db # Keep get_db import
# --- END CORRECTION ---
from app.models.user import User as UserModel
from app.crud.crud_user import user as crud_user
from app.core.config import settings # Importar settings

# Define oauth2_scheme HERE using the correct tokenUrl
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token") # Adjusted tokenUrl

# --- get_current_user logic remains the same ---
async def get_current_user_from_token(
    db: AsyncSession = Depends(get_db), token: str = Depends(oauth2_scheme)
) -> UserModel:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    payload = security.decode_access_token(token)
    if payload is None:
        raise credentials_exception

    user_id_str = payload.get("sub")
    if user_id_str is None:
        raise credentials_exception

    try:
         user_id = int(user_id_str)
    except ValueError:
         raise credentials_exception

    user = await crud_user.get(db, id=user_id)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(
    current_user: UserModel = Depends(get_current_user_from_token),
) -> UserModel:
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# You might add RoleChecker here later if needed


# --- DEPENDÊNCIA DA CHAVE DE API (X-API-Key) ---
api_key_header_scheme = APIKeyHeader(name="X-API-Key")

async def get_api_key(api_key: str = Depends(api_key_header_scheme)) -> str:
    """
    Verifica se a X-API-Key enviada no header é válida.
    """
    if not settings.INTERNAL_API_KEY:
        # Erro de segurança: a chave nem está configurada no servidor
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="INTERNAL_API_KEY não está configurada no servidor",
        )
    # Compara as chaves de forma segura para evitar timing attacks
    if not secrets.compare_digest(api_key, settings.INTERNAL_API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Chave de API inválida ou ausente",
        )
    return api_key
# --- FIM DEPENDÊNCIA DA CHAVE DE API ---