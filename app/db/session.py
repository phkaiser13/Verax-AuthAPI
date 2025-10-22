from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from app.core.config import settings # Importa as configurações locais
from typing import AsyncGenerator

# ASYNC_SQLALCHEMY_DATABASE_URL = settings.DATABASE_URL # Já deve estar com asyncpg do .env
# Se precisar trocar o driver explicitamente:
ASYNC_SQLALCHEMY_DATABASE_URL = settings.DATABASE_URL.replace("postgresql+psycopg2", "postgresql+asyncpg")

async_engine = create_async_engine(
    ASYNC_SQLALCHEMY_DATABASE_URL,
    pool_pre_ping=True,
    echo=False # Mude para True para ver SQL gerado no console
)

AsyncSessionLocal = sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

# Dependência para injeção de sessão nas rotas
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as db:
        try:
            yield db
        finally:
            await db.close()