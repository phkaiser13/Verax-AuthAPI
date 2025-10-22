# auth_api/app/core/config.py
import os
import logging
from pydantic_settings import BaseSettings
from pydantic import EmailStr
from pathlib import Path

# --- 1. Definir o caminho para o .env ---
# Isso garante que o Pydantic encontre o .env, não importa de onde o script é executado.
# Sobe 3 níveis: app/core/config.py -> app/core/ -> app/ -> (raiz do projeto 'auth_api')
BASE_DIR = Path(__file__).resolve().parent.parent.parent
ENV_FILE_PATH = BASE_DIR / ".env"

# Log de debug para verificar se o caminho está correto
# print(f"DEBUG: Procurando arquivo .env em: {ENV_FILE_PATH}")


class Settings(BaseSettings):
    # --- 2. Definir TODAS as variáveis do .env ---
    # O Pydantic irá carregá-las automaticamente do .env (usando o caminho abaixo)
    
    # Core
    DATABASE_URL: str
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Refresh Token
    REFRESH_SECRET_KEY: str
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # Email SMTP (Não usamos mais os.getenv, Pydantic cuida disso)
    EMAIL_HOST: str = "localhost"
    EMAIL_PORT: int = 2525
    EMAIL_USERNAME: str | None = None
    EMAIL_PASSWORD: str | None = None
    EMAIL_FROM: EmailStr = "noreply@example.com"
    EMAIL_FROM_NAME: str | None = "Auth API"
    EMAIL_USE_TLS: bool = True
    EMAIL_USE_SSL: bool = False
    
    # Email Links
    VERIFICATION_URL_BASE: str = "http://localhost:8000/verify"
    EMAIL_VERIFICATION_TOKEN_EXPIRE_MINUTES: int = 60
    
    # Password Reset
    RESET_PASSWORD_SECRET_KEY: str | None = None
    RESET_PASSWORD_TOKEN_EXPIRE_MINUTES: int = 30
    RESET_PASSWORD_URL_BASE: str = "http://localhost:8000/reset-password"

    # --- 3. Configurar o Pydantic para ler o .env ---
    class Config:
        case_sensitive = True
        env_file = ENV_FILE_PATH       # Caminho explícito para o .env
        env_file_encoding = 'utf-8'   # Codificação correta

# --- 4. Instanciar as configurações ---
try:
    settings = Settings()
    # print(f"DEBUG: DATABASE_URL carregada: {settings.DATABASE_URL[:20]}...") # Descomente para testar
except Exception as e:
    logging.error(f"FATAL: Erro ao carregar 'settings' a partir do .env em {ENV_FILE_PATH}: {e}")
    # Se falhar aqui, o programa vai parar, o que é bom.
    raise e
