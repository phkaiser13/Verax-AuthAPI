from loguru import logger
from datetime import timedelta
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

router = APIRouter()

# --- REMOVE get_current_user_from_token and get_current_active_user from here ---
# They are now correctly placed in dependencies.py

@router.post("/token", response_model=Token)
async def login_for_access_token(
    db: AsyncSession = Depends(get_db),
    form_data: OAuth2PasswordRequestForm = Depends(),
) -> Any:
    user = await crud_user.authenticate(
        db, email=form_data.username, password=form_data.password
    )
    # A verificação de is_verified e is_active agora está dentro do authenticate
    if not user:
        # Se authenticate retornou None por email/senha errados OU por não estar ativo/verificado
        user_check = await crud_user.get_by_email(db, email=form_data.username)
        if user_check and (not user_check.is_active or not user_check.is_verified):
             raise HTTPException(
                 status_code=status.HTTP_400_BAD_REQUEST,
                 detail="Conta inativa ou e-mail não verificado. Verifique seu e-mail."
             )
        # Se não achou o usuário ou a senha está errada
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect email or password"
        )
    # Se passou, o usuário é válido, ativo e verificado
    # ... (código para gerar tokens permanece igual) ...
    access_token = security.create_access_token(data={"sub": str(user.id)})
    refresh_token_str, expires_at = security.create_refresh_token(data={"sub": str(user.id)})
    await crud_refresh_token.create_refresh_token(
        db, user=user, token=refresh_token_str, expires_at=expires_at
    )
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
    refresh_token_str = refresh_request.refresh_token
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # 1. Decodifica o payload (verifica assinatura e expiração básica)
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

    # 2. Verifica se o token existe no banco, não está revogado e não expirou
    db_refresh_token = await crud_refresh_token.get_refresh_token(db, token=refresh_token_str)
    if not db_refresh_token or db_refresh_token.user_id != user_id:
        # Se não achou no DB (ou pertence a outro user), o token é inválido/revogado/expirado
        # Logar tentativa de uso de token inválido pode ser útil aqui
        raise credentials_exception

    # 3. (Opcional, mas recomendado: Rotação de Refresh Token)
    # Revoga o token atual para que não possa ser reutilizado
    await crud_refresh_token.revoke_refresh_token(db, token=refresh_token_str)

    # Busca o usuário para gerar novos tokens
    user = await crud_user.get(db, id=user_id)
    if not user or not user.is_active:
        raise credentials_exception # Usuário pode ter sido desativado

    # 4. Gera um NOVO Access Token
    new_access_token = security.create_access_token(data={"sub": str(user.id)})

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

@router.get("/verify-email/{token}", response_model=UserSchema)
async def verify_email(
    *,
    db: AsyncSession = Depends(get_db),
    token: str = Path(...) # Pega o token da URL
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
    # Opcional: Redirecionar para uma página de sucesso no frontend
    # from fastapi.responses import RedirectResponse
    # return RedirectResponse(url="/login?verified=true")
    return user # Retorna os dados do usuário verificado

@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    *,
    db: AsyncSession = Depends(get_db),
    refresh_request: RefreshTokenRequest # Requer o refresh token para revogá-lo
    # Ou poderia pegar o token do cabeçalho se fosse mais complexo
):
    """
    Revoga o Refresh Token fornecido.
    """
    success = await crud_refresh_token.revoke_refresh_token(db, token=refresh_request.refresh_token)
    if not success:
        # Não levanta erro, mas poderia logar se o token já era inválido
        pass
    return None # Retorna 204 No Content

@router.get("/me", response_model=UserSchema)
async def read_users_me(
    current_user: UserModel = Depends(get_current_active_user), # Use dependency directly
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
    
    # IMPORTANTE: Por segurança, NÃO retorne 404 se o usuário não existir.
    # Sempre retorne 202 para evitar que atacantes descubram emails cadastrados.
    if user and user.is_active:
        # Usuário existe e está ativo, gerar token e enviar email
        try:
            db_user, reset_token = await crud_user.generate_password_reset_token(db, user=user)
            
            # Adiciona o envio do email na fila em background
            background_tasks.add_task(
                send_password_reset_email,
                email_to=db_user.email,
                reset_token=reset_token
            )
            logger.info(f"Solicitação de reset de senha para: {user.email}")
            
        except Exception as e:
            # Se falhar ao gerar token ou enviar email, loga o erro mas não vaza a informação
            logger.error(f"Erro no fluxo /forgot-password para {request_body.email}: {e}")
            # Ainda retorna 202
            
    else:
        # Usuário não encontrado ou inativo, loga e retorna 202
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
    
    # 1. Decodifica o token JWT (verifica assinatura, expiração)
    payload = security.decode_password_reset_token(token)
    if not payload or not payload.get("sub"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token de redefinição inválido ou expirado (JWT)"
        )
    
    email = payload["sub"]
    
    # 2. Busca o usuário pelo token HASH no banco (garante que não foi usado)
    user = await crud_user.get_user_by_reset_token(db, token=token)
    
    if not user or user.email != email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token de redefinição inválido, expirado ou já utilizado (DB)"
        )
        
    # 3. Usuário e token são válidos. Atualiza a senha.
    try:
        updated_user = await crud_user.reset_password(
            db, user=user, new_password=new_password
        )
        logger.info(f"Senha redefinida com sucesso para o usuário: {user.email}")
        
        # Opcional: Enviar um email de confirmação "Sua senha foi alterada"
        
        return updated_user
        
    except Exception as e:
        logger.error(f"Erro ao tentar redefinir a senha para {user.email}: {e}")
        await db.rollback() # Garante que a transação falhe
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Ocorreu um erro ao atualizar sua senha."
        )