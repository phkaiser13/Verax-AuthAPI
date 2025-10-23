# auth_api/app/core/security.py
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional # Adicionar Optional
from passlib.context import CryptContext
from jose import jwt, JWTError
from .config import settings # Keep importing settings
import secrets
from app.models.user import User as UserModel # Importar o modelo User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ... (constantes de nível superior removidas) ...


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
def create_access_token(
    user: UserModel, # Recebe o objeto User completo
    requested_scopes: Optional[list[str]] = None
) -> str:
    
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    # --- INÍCIO: Construir Payload com Claims OIDC Padrão ---
    to_encode: Dict[str, Any] = {
        "iss": settings.JWT_ISSUER,            # Issuer (Quem emitiu)
        "aud": settings.JWT_AUDIENCE,          # Audience (Para quem)
        "iat": now,                            # Issued At (Quando foi emitido)
        "nbf": now,                            # Not Before (Não válido antes de)
        "exp": expire,                         # Expiration Time (Expiração)
        "sub": str(user.id),                   # Subject (ID do usuário)
        "token_type": "access",                # Tipo do token (nosso claim customizado)
        "email": user.email,                   # Claim OIDC: email
        "email_verified": user.is_verified,    # Claim OIDC: email_verified
        # Adicionar 'name' se full_name existir
        **({"name": user.full_name} if user.full_name else {}) 
    }
    # --- FIM: Claims OIDC Padrão ---

    # --- INÍCIO: Injeção de Claims Customizados (scopes) ---
    if user.custom_claims and requested_scopes:
        for scope in requested_scopes:
            if scope in user.custom_claims:
                # Evita sobrescrever claims OIDC padrão se houver conflito
                if scope not in to_encode: 
                    to_encode[scope] = user.custom_claims.get(scope)
    # --- FIM: Injeção de Claims Customizados ---

    encoded_jwt = jwt.encode(
        to_encode, 
        settings.SECRET_KEY, 
        algorithm=settings.ALGORITHM
    )
    return encoded_jwt

def decode_access_token(token: str) -> Dict | None:
    try:
        # --- MODIFICADO: Adicionar validação de Audience ---
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            audience=settings.JWT_AUDIENCE, # Valida o 'aud' claim
            options={"verify_iss": True, "verify_aud": True} # Força validação de iss e aud
        )
        # --- FIM MODIFICAÇÃO ---
        return payload
    except JWTError:
        return None

# --- Funções para Refresh Token ---
def create_refresh_token(data: Dict[str, Any]) -> tuple[str, datetime]:
    # Refresh tokens geralmente NÃO contêm claims OIDC, apenas o necessário
    to_encode = data.copy()
    expires_delta = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({
        "iss": settings.JWT_ISSUER, # É bom incluir o issuer
        "exp": expire, 
        "token_type": "refresh"
    }) 
    encoded_jwt = jwt.encode(to_encode, settings.REFRESH_SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt, expire.replace(tzinfo=None)

def decode_refresh_token(token: str) -> Dict | None:
    try:
        payload = jwt.decode(
            token,
            settings.REFRESH_SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            options={"verify_iss": True, "verify_aud": False} # Verifica issuer, ignora audience
        )
        if payload.get("token_type") != "refresh":
             return None
        return payload
    except JWTError:
        return None

# --- Funções para Reset Token ---
def create_password_reset_token(email: str) -> tuple[str, datetime]:
    # Reset tokens também não precisam de claims OIDC
    reset_secret = settings.RESET_PASSWORD_SECRET_KEY or settings.SECRET_KEY
    expires_delta = timedelta(minutes=settings.RESET_PASSWORD_TOKEN_EXPIRE_MINUTES)
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode = {
        "iss": settings.JWT_ISSUER, # É bom incluir o issuer
        "aud": settings.JWT_AUDIENCE, # Pode ser útil
        "exp": expire,
        "nbf": datetime.now(timezone.utc),
        "sub": email,
        "token_type": "password_reset"
    }
    encoded_jwt = jwt.encode(to_encode, reset_secret, algorithm=settings.ALGORITHM)
    return encoded_jwt, expire.replace(tzinfo=None)

def decode_password_reset_token(token: str) -> Dict | None:
    try:
        reset_secret = settings.RESET_PASSWORD_SECRET_KEY or settings.SECRET_KEY
        payload = jwt.decode(
            token,
            reset_secret,
            algorithms=[settings.ALGORITHM],
            options={"verify_iss": True, "verify_aud": True} # Verifica issuer e audience
        )
        if payload.get("token_type") != "password_reset" or "sub" not in payload:
             return None
        return payload
    except JWTError:
        return None