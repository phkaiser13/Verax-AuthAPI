# auth_api/app/schemas/token.py
from pydantic import BaseModel
from typing import Literal, List, Optional # Importar Literal, List, Optional

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

class TokenPayload(BaseModel):
    sub: str | None = None
    exp: int | None = None
    token_type: str | None = None
    # Adicionar claim para challenge token ou AMR
    # mfa_passed: bool | None = None # Poderia ser usado no challenge
    amr: Optional[List[str]] = None # Authentication Methods Reference

class RefreshTokenRequest(BaseModel):
    refresh_token: str

# --- NOVO SCHEMA: Resposta MFA Obrigatório ---
class MFARequiredResponse(BaseModel):
    """Resposta indicando que a verificação MFA é necessária."""
    detail: Literal["MFA verification required"] = "MFA verification required"
    mfa_challenge_token: str # Um token temporário para a próxima etapa
# --- FIM NOVO SCHEMA ---
