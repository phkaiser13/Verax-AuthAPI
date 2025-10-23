# auth_api/app/api/endpoints/auth.py
from loguru import logger
from datetime import datetime, timedelta, timezone # Importar datetime, timezone
from typing import Any
from app.crud import crud_refresh_token # Importar CRUD do refresh token
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.dependencies import get_current_active_user, get_db # Certifique-se que get_db está aqui
from app.crud.crud_user import user as crud_user
from app.db.session import get_db
from app.core import security # Keep for security functions
from app.core.config import settings
from app.schemas.token import Token, RefreshTokenRequest # Importar RefreshTokenRequest
from app.schemas.user import User as UserSchema
from app.models.user import User as UserModel
from app.schemas.user import ForgotPasswordRequest, ResetPasswordRequest
from app.services.email_service import send_password_reset_email
from fastapi import Path, BackgroundTasks # Adicionar Path E BackgroundTasks
# --- IMPORT FROM DEPENDENCIES ---
from app.api.dependencies import get_current_active_user, oauth2_scheme
# --- END IMPORT CORRECTION ---
# --- IMPORT CUSTOM EXCEPTION ---
from app.core.exceptions import AccountLockedException
# --- END IMPORT ---

router = APIRouter()

# ... (get_current_user_from_token e get_current_active_user removidos daqui) ...

@router.post("/token", response_model=Token)
async def login_for_access_token(
    db: AsyncSession = Depends(get_db),
    form_data: OAuth2PasswordRequestForm = Depends(),
) -> Any:
    """
    Login para obter Access e Refresh tokens.
    
    Opcionalmente, pode receber 'scope' no form-data (ex: "roles permissions")
    para injetar claims no Access Token.
    """
    try:
        # Lógica de autenticação (EXISTENTE)
        user = await crud_user.authenticate(
            db, email=form_data.username, password=form_data.password
        )
    except AccountLockedException as e:
        # Captura a exceção de conta bloqueada (EXISTENTE)
        detail_msg = "Account locked due to too many failed login attempts."
        if e.locked_until:
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            if e.locked_until > now: # Checa se o bloqueio ainda está ativo
                remaining = e.locked_until - now
                # Arredonda para cima os minutos
                remaining_minutes = int(remaining.total_seconds() // 60) + 1 
                detail_msg = f"Account locked. Try again in {remaining_minutes} minute(s)."
        
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=detail_msg
        )
        
    # Verificação de usuário ativo/verificado (EXISTENTE)
    if not user:
        user_check = await crud_user.get_by_email(db, email=form_data.username)
        
        if user_check and (not user_check.is_active or not user_check.is_verified):
             raise HTTPException(
                 status_code=status.HTTP_400_BAD_REQUEST,
                 detail="Conta inativa ou e-mail não verificado. Verifique seu e-mail."
             )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect email or password"
        )
    
    # Se passou, o usuário é válido, ativo e verificado
    
    # --- LER SCOPES DO FORMULÁRIO (EXISTENTE) ---
    requested_scopes = form_data.scopes
    # --- FIM LEITURA SCOPES ---

    # --- MODIFICADO: GERAR TOKENS (PASSANDO USER E SCOPES) ---
    access_token = security.create_access_token(
        user=user, # Passa o objeto User completo
        requested_scopes=requested_scopes # Passa os scopes solicitados
    )
    
    refresh_token_str, expires_at = security.create_refresh_token(
        data={"sub": str(user.id)} # Refresh token continua só com 'sub'
    )
    
    await crud_refresh_token.create_refresh_token(
        db, user=user, token=refresh_token_str, expires_at=expires_at
    )
    # --- FIM GERAÇÃO TOKENS ---

    return {
        "access_token": access_token,
        "refresh_token": refresh_token_str,
        "token_type": "bearer",
    }


@router.post("/refresh", response_model=Token)
async def refresh_access_token(
    *,
    db: AsyncSession = Depends(get_db),
    refresh_request: RefreshTokenRequest
) -> Any:
    """
    Recebe um Refresh Token válido e retorna um novo par de Access e Refresh Tokens.
    (Opcional: Rotação de Refresh Token)
    """
    # --- Nenhuma mudança necessária aqui ---
    # O refresh token e o novo access token gerado pelo refresh
    # NÃO contêm os claims OIDC de usuário (email, name, etc.) nem os custom_claims.
    # Isso é o comportamento padrão e esperado.
    # Se o cliente precisar de claims atualizados, ele refaz o login (/token).
    refresh_token_str = refresh_request.refresh_token
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # 1. Decodifica o payload
    payload = security.decode_refresh_token(refresh_token_str)
    if payload is None:
        raise credentials_exception

    user_id_str = payload.get("sub")
    if user_id_str is None:
        raise credentials_exception
    try:
        user_id = int(user_id_str)
    except ValueError:
        raise credentials_exception

    # 2. Verifica se o token existe no banco
    db_refresh_token = await crud_refresh_token.get_refresh_token(db, token=refresh_token_str)
    if not db_refresh_token or db_refresh_token.user_id != user_id:
        raise credentials_exception

    # 3. Rotação de Refresh Token
    await crud_refresh_token.revoke_refresh_token(db, token=refresh_token_str)

    # Busca o usuário
    user = await crud_user.get(db, id=user_id)
    if not user or not user.is_active:
        raise credentials_exception 

    # 4. Gera um NOVO Access Token (sem claims OIDC/custom)
    new_access_token = security.create_access_token(user=user) # Passa o user, mas sem scopes

    # 5. Gera um NOVO Refresh Token (para rotação)
    new_refresh_token_str, new_expires_at = security.create_refresh_token(data={"sub": str(user.id)})

    # 6. Salva o hash do NOVO Refresh Token no banco
    await crud_refresh_token.create_refresh_token(
        db, user=user, token=new_refresh_token_str, expires_at=new_expires_at
    )

    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token_str,
        "token_type": "bearer",
    }

# --- Os endpoints /verify-email, /logout, /me, /forgot-password, /reset-password ---
# --- permanecem EXATAMENTE IGUAIS ---

@router.get("/verify-email/{token}", response_model=UserSchema)
async def verify_email(
    *,
    db: AsyncSession = Depends(get_db),
    token: str = Path(...) 
):
    """
    Verifica o email do usuário usando o token recebido.
    """
    user = await crud_user.verify_user_email(db, token=token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token de verificação inválido ou expirado",
        )
    logger.info(f"Email verificado com sucesso para usuário ID: {user.id}")
    return user 

@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    *,
    db: AsyncSession = Depends(get_db),
    refresh_request: RefreshTokenRequest
):
    """
    Revoga o Refresh Token fornecido.
    """
    success = await crud_refresh_token.revoke_refresh_token(db, token=refresh_request.refresh_token)
    if not success:
        pass
    return None 

@router.get("/me", response_model=UserSchema)
async def read_users_me(
    current_user: UserModel = Depends(get_current_active_user),
) -> Any:
    """
    Retorna os dados do usuário logado (validando o token).
    """
    return current_user

@router.post("/forgot-password", status_code=status.HTTP_202_ACCEPTED)
async def forgot_password(
    *,
    db: AsyncSession = Depends(get_db),
    request_body: ForgotPasswordRequest,
    background_tasks: BackgroundTasks
):
    """
    Inicia o fluxo de redefinição de senha.
    Envia um email para o usuário (se ele existir e estiver ativo).
    """
    user = await crud_user.get_by_email(db, email=request_body.email)
    
    if user and user.is_active:
        try:
            db_user, reset_token = await crud_user.generate_password_reset_token(db, user=user)
            
            background_tasks.add_task(
                send_password_reset_email,
                email_to=db_user.email,
                reset_token=reset_token
            )
            logger.info(f"Solicitação de reset de senha para: {user.email}")
            
        except Exception as e:
            logger.error(f"Erro no fluxo /forgot-password para {request_body.email}: {e}")
            
    else:
        logger.warning(f"Tentativa de /forgot-password para email não existente ou inativo: {request_body.email}")

    return {"msg": "Se um usuário com esse email existir e estiver ativo, um link de redefinição será enviado."}


@router.post("/reset-password", response_model=UserSchema)
async def reset_password(
    *,
    db: AsyncSession = Depends(get_db),
    request_body: ResetPasswordRequest
):
    """
    Recebe o token de reset e a nova senha, e atualiza o usuário.
    """
    token = request_body.token
    new_password = request_body.new_password
    
    # 1. Decodifica o token JWT
    payload = security.decode_password_reset_token(token)
    if not payload or not payload.get("sub"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token de redefinição inválido ou expirado (JWT)"
        )
    
    email = payload["sub"]
    
    # 2. Busca o usuário pelo token HASH no banco
    user = await crud_user.get_user_by_reset_token(db, token=token)
    
    if not user or user.email != email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token de redefinição inválido, expirado ou já utilizado (DB)"
        )
        
    # 3. Usuário e token são válidos. Atualiza a senha.
    try:
        # A função reset_password já limpa o lockout
        updated_user = await crud_user.reset_password(
            db, user=user, new_password=new_password
        )
        logger.info(f"Senha redefinida com sucesso para o usuário: {user.email}")
        
        return updated_user
        
    except Exception as e:
        logger.error(f"Erro ao tentar redefinir a senha para {user.email}: {e}")
        await db.rollback() 
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Ocorreu um erro ao atualizar sua senha."
        )