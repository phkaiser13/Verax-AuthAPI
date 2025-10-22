# alembic/env.py
import asyncio
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine

from alembic import context

# --- 1. Importar Base e Modelos ---
# Adicione sys.path para que o alembic encontre sua pasta 'app'
import os
import sys
from pathlib import Path
# Sobe dois níveis (alembic/ -> raiz) e adiciona ao path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from app.db.base import Base
from app.models import user # noqa F401
from app.models import refresh_token # noqa F401
# --- Fim Importar Modelos ---


# --- 2. Carregar Configurações do App ---
from app.core.config import settings
# --- Fim Carregar Configurações ---


# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# --- 3. Definir o sqlalchemy.url dinamicamente ---
# Substitui o 'sqlalchemy.url' do alembic.ini pelo do nosso app
# Garante que a URL seja compatível com asyncpg
db_url = settings.DATABASE_URL
if "postgresql+psycopg2" in db_url:
    db_url = db_url.replace("postgresql+psycopg2", "postgresql+asyncpg")
config.set_main_option("sqlalchemy.url", db_url)
# --- Fim Definição URL ---


# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# add your model's MetaData object here
# for 'autogenerate' support
# target_metadata = mymodel.Base.metadata
target_metadata = Base.metadata # --- 4. Apontar para a Base do nosso app ---

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True # Adicionado para detectar mudanças de tipo (ex: VARCHAR(100))
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection, 
        target_metadata=target_metadata,
        compare_type=True # Adicionado para detectar mudanças de tipo
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    
    # --- 5. Configuração Assíncrona ---
    connectable = create_async_engine(
        config.get_main_option("sqlalchemy.url"),
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()
    # --- Fim Configuração Assíncrona ---


if context.is_offline_mode():
    run_migrations_offline()
else:
    # --- 6. Rodar no loop de eventos asyncio ---
    asyncio.run(run_migrations_online())
    # --- Fim asyncio ---