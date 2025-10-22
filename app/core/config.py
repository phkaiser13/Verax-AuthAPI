# auth_api/app/core/config.py
import os
from pydantic_settings import BaseSettings
from dotenv import load_dotenv
from pydantic import EmailStr # Manter a importação

load_dotenv()

class Settings(BaseSettings):
    # ... (DATABASE_URL, SECRET_KEY, ALGORITHM, etc.) ...

    # --- Configurações de Email ---
    EMAIL_HOST: str = os.getenv("EMAIL_HOST", "localhost")
    EMAIL_PORT: int = int(os.getenv("EMAIL_PORT", 2525))
    EMAIL_USERNAME: str | None = os.getenv("EMAIL_USERNAME")
    EMAIL_PASSWORD: str | None = os.getenv("EMAIL_PASSWORD")

    # --- CORREÇÃO AQUI ---
    # Apenas defina o tipo EmailStr e atribua o valor do getenv diretamente.
    # Pydantic validará se o valor carregado é um email válido.
    EMAIL_FROM: EmailStr = os.getenv("EMAIL_FROM", "noreply@example.com")
    # --- FIM DA CORREÇÃO ---

    EMAIL_FROM_NAME: str | None = os.getenv("EMAIL_FROM_NAME", "Auth API")
    EMAIL_USE_TLS: bool = os.getenv("EMAIL_USE_TLS", "true").lower() == "true"
    EMAIL_USE_SSL: bool = os.getenv("EMAIL_USE_SSL", "false").lower() == "true"
    VERIFICATION_URL_BASE: str = os.getenv("VERIFICATION_URL_BASE", "http://localhost:8000/verify") # URL base para links

    EMAIL_VERIFICATION_TOKEN_EXPIRE_MINUTES: int = 60

    # --- Configurações de Reset de Senha ---
    RESET_PASSWORD_SECRET_KEY: str | None = os.getenv("RESET_PASSWORD_SECRET_KEY")
    RESET_PASSWORD_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("RESET_PASSWORD_TOKEN_EXPIRE_MINUTES", 30))
    RESET_PASSWORD_URL_BASE: str = os.getenv("RESET_PASSWORD_URL_BASE", "http://localhost:8000/reset-password") # URL base para links de reset


    class Config:
        case_sensitive = True

settings = Settings()