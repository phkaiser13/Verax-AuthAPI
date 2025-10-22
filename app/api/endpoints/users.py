from typing import Any, List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.dependencies import get_current_active_user
from app.crud.crud_user import user as crud_user
from app.db.session import get_db
from app.schemas.user import User as UserSchema, UserCreate, UserUpdate
# Importar dependência de autenticação do módulo auth
from app.models.user import User as UserModel
from app.services.email_service import send_verification_email # Importar serviço de email
from fastapi import BackgroundTasks # Importar BackgroundTasks

router = APIRouter()

# Opcional: Proteger endpoints de usuário (ex: só admins podem criar/listar)
# Você precisaria adicionar um campo 'is_superuser' ao modelo e schema User
# e criar uma dependência RoleChecker como no VR Sales.
# Por simplicidade inicial, vamos deixar aberto ou usar apenas a autenticação básica.

@router.post("/", response_model=UserSchema, status_code=status.HTTP_201_CREATED)
async def create_user(
    *,
    db: AsyncSession = Depends(get_db),
    user_in: UserCreate,
    background_tasks: BackgroundTasks # Adicionar BackgroundTasks
    # current_user: UserModel = Depends(get_current_active_user) # Descomente se proteger
) -> Any:
    """
    Cria um novo usuário (registro) e envia email de verificação.
    """
    user = await crud_user.get_by_email(db, email=user_in.email)
    if user:
        raise HTTPException(
            status_code=400,
            detail="The user with this email already exists in the system.",
        )
    # create agora retorna o usuário E o token
    db_user, verification_token = await crud_user.create(db, obj_in=user_in)

    # --- Enviar email em background ---
    background_tasks.add_task(
        send_verification_email,
        email_to=db_user.email,
        verification_token=verification_token
    )
    # --- Fim envio email ---

    # Retorna o usuário criado (sem o token)
    return db_user

@router.get("/", response_model=List[UserSchema])
async def read_users(
    db: AsyncSession = Depends(get_db),
    skip: int = 0,
    limit: int = 100,
    # current_user: UserModel = Depends(get_current_active_user) # Descomente se proteger
) -> Any:
    """
    Retorna uma lista de usuários. (Idealmente protegido para admins)
    """
    users = await crud_user.get_multi(db, skip=skip, limit=limit)
    return users

@router.get("/{user_id}", response_model=UserSchema)
async def read_user_by_id(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    # current_user: UserModel = Depends(get_current_active_user) # Descomente se proteger
) -> Any:
    """
    Busca um usuário pelo ID.
    """
    user = await crud_user.get(db, id=user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    # Adicionar verificação se o usuário logado pode ver este usuário
    return user

@router.put("/me", response_model=UserSchema)
async def update_user_me(
    *,
    db: AsyncSession = Depends(get_db),
    user_in: UserUpdate,
    current_user: UserModel = Depends(get_current_active_user),
) -> Any:
    """
    Atualiza os dados do próprio usuário logado.
    """
    user = await crud_user.update(db, db_obj=current_user, obj_in=user_in)
    return user