# auth_api/app/schemas/token.py
from pydantic import BaseModel

class Token(BaseModel):
    access_token: str
    refresh_token: str # Adicionado
    token_type: str

class TokenPayload(BaseModel):
    sub: str | None = None # Subject (ID do usuário)
    # Adicionar exp se quiser verificar expiração antes de chamar o security.decode
    exp: int | None = None
    # Adicionar tipo de token se quiser diferenciar AT de RT no payload
    # token_type: str | None = None

class RefreshTokenRequest(BaseModel):
    refresh_token: str