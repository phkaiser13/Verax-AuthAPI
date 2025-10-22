# auth_api/app/schemas/user.py
from pydantic import BaseModel, EmailStr, Field, validator, field_validator # Adicionar field_validator
from typing import Optional
from datetime import datetime
import re # Importar re para regex

# Função de validação de senha
def password_strength_validator(password: str) -> str:
    if len(password) < 8:
        raise ValueError('A senha deve ter pelo menos 8 caracteres')
    if not re.search(r"[a-z]", password):
        raise ValueError('A senha deve conter pelo menos uma letra minúscula')
    if not re.search(r"[A-Z]", password):
        raise ValueError('A senha deve conter pelo menos uma letra maiúscula')
    if not re.search(r"[0-9]", password):
        raise ValueError('A senha deve conter pelo menos um número')
    if not re.search(r"[\W_]", password): # \W corresponde a não-alfanumérico
        raise ValueError('A senha deve conter pelo menos um caractere especial')
    return password

class UserBase(BaseModel):
    email: EmailStr
    full_name: Optional[str] = None
    is_active: Optional[bool] = True

class UserCreate(UserBase):
    password: str = Field(..., min_length=8) # min_length ainda útil para feedback inicial

    # Aplica a validação customizada à senha usando Pydantic v2
    @field_validator('password')
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        return password_strength_validator(v)


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    password: Optional[str] = Field(None, min_length=8)
    is_active: Optional[bool] = None

    # Aplica a validação customizada à senha também na atualização, se fornecida
    @field_validator('password')
    @classmethod
    def validate_update_password_strength(cls, v: Optional[str]) -> Optional[str]:
        if v is not None: # Só valida se a senha for fornecida
            return password_strength_validator(v)
        return v # Retorna None se não for fornecida

class User(UserBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True