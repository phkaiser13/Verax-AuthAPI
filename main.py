# auth_api/main.py
from fastapi import FastAPI, Request, Depends # Adicionar Request E Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse # Adicionar JSONResponse

# --- Adicionar imports do slowapi ---
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
# --- Fim imports slowapi ---
from app.db.session import dispose_engine # Import the dispose function
# Importar routers
from app.api.endpoints import auth, users, mgmt # Importar mgmt
# Importar dependência de chave de API
from app.api.dependencies import get_api_key


# Importar modelos para Alembic/Base.metadata
from app.db.base import Base # noqa
from app.models import user, refresh_token # noqa Adicionar refresh_token

# Importar configurações, logging, exception handlers (opcional)
# from app.core.logging_config import setup_logging
# from app.core.exception_handler import global_exception_handler

# setup_logging() # Configura logging

# --- Configurar o Limiter ---
# (EXISTENTE)
limiter = Limiter(key_func=get_remote_address, default_limits=["10/minute"]) 
# --- Fim configuração Limiter ---

app = FastAPI(
    title="Auth API",
    description="API Centralizada de Autenticação",
    version="1.0.0"
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
# --- ADICIONAR O MIDDLEWARE (EXISTENTE) ---
app.add_middleware(SlowAPIMiddleware) 
# --- FIM ADIÇÃO ---

# Configurar CORS (EXISTENTE)
origins = [
    "http://localhost:5173", # Exemplo: Frontend VR Sales
    "http://localhost:3000", # Exemplo: Outro frontend
    "http://localhost:8000", # Exemplo: API VR Sales fazendo validação
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# app.add_exception_handler(Exception, global_exception_handler)

# Incluir routers da API
api_prefix = "/api/v1"

app.include_router(auth.router, prefix=f"{api_prefix}/auth", tags=["Authentication"])
app.include_router(users.router, prefix=f"{api_prefix}/users", tags=["Users"])

# --- NOVO: ADICIONAR ROUTER DE GERENCIAMENTO (PROTEGIDO) ---
app.include_router(
    mgmt.router,
    prefix=f"{api_prefix}/mgmt",
    tags=["Management"],
    dependencies=[Depends(get_api_key)] # Protege TODAS as rotas em /mgmt
)
# --- FIM ADIÇÃO ---


@app.on_event("shutdown")
async def shutdown_event():
    print("Shutting down: Disposing database engine...")
    await dispose_engine()
    print("Database engine disposed.")

@app.get("/")
def read_root():
    return {"message": "Auth API is running!"}