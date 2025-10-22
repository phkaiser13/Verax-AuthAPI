# auth_api/app/db/initial_data.py
import asyncio
import logging
import os
# Configuração básica de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 1. Importar a Base e a engine assíncrona
from app.db.base import Base
from app.db.session import async_engine

# 2. Importar TODOS os seus modelos para que Base.metadata os conheça
from app.models import user # noqa F401
from app.models.refresh_token import RefreshToken # <-- ADD OR ENSURE THIS LINE EXISTS
# Adicione aqui importações para outros modelos que você criar no futuro
# Ex: from app.models import token_blacklist # noqa F401

async def init_db() -> None:
    logger.info("Iniciando a recriação do banco de dados (DROP ALL / CREATE ALL)...")
    async with async_engine.begin() as conn:
        logger.info("Removendo todas as tabelas existentes (se houver)...")
        # drop_all removerá tabelas
        await conn.run_sync(Base.metadata.drop_all)
        logger.info("Tabelas removidas.")

        logger.info("Criando todas as tabelas definidas nos modelos...")
        # create_all criará as tabelas
        await conn.run_sync(Base.metadata.create_all)
        logger.info("Tabelas criadas com sucesso.")

    logger.info("Processo de inicialização do banco de dados concluído.")
    # Garante que a engine seja descartada corretamente ao final
    await async_engine.dispose()

async def main() -> None:
    await init_db()

if __name__ == "__main__":
    # Define a política de loop de eventos do asyncio (importante no Windows)
    if os.name == 'nt': # Verifica se é Windows
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    import os # Importa os aqui para usar na verificação do SO
    
    try:
        asyncio.run(main())
    except Exception as e:
        logger.error(f"Ocorreu um erro durante a inicialização do banco de dados: {e}")
        # Adicione mais detalhes se necessário, como traceback
        import traceback
        logger.error(traceback.format_exc())