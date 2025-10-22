# auth_api/app/services/email_service.py
import emails
from emails.template import JinjaTemplate
from app.core.config import settings
from loguru import logger
from typing import Dict, Any

async def send_email_async(
    email_to: str,
    subject_template: str = "",
    html_template: str = "",
    environment: Dict[str, Any] = {},
) -> bool:
    """Envia um email de forma assíncrona."""
    assert settings.EMAIL_FROM, "EMAIL_FROM deve estar configurado"

    message = emails.Message(
        subject=JinjaTemplate(subject_template),
        html=JinjaTemplate(html_template),
        mail_from=(settings.EMAIL_FROM_NAME, settings.EMAIL_FROM),
    )

    smtp_options = {
        "host": settings.EMAIL_HOST,
        "port": settings.EMAIL_PORT,
        "tls": settings.EMAIL_USE_TLS,
        "ssl": settings.EMAIL_USE_SSL,
    }
    if settings.EMAIL_USERNAME:
        smtp_options["user"] = settings.EMAIL_USERNAME
    if settings.EMAIL_PASSWORD:
        smtp_options["password"] = settings.EMAIL_PASSWORD

    try:
        # A biblioteca 'emails' não é nativamente async, rodamos em thread separada
        # Para produção real, usar libs async ou tarefas em background (Celery) seria melhor
        loop = asyncio.get_running_loop()
        response = await loop.run_in_executor(
            None, # Usa o executor de thread padrão
            message.send, # Função a ser executada
            email_to, # Argumentos para message.send
            smtp_options
        )
        logger.info(f"Email enviado para {email_to}, Assunto: {subject_template}. Resposta SMTP: {response.status_code}")
        # Verificar response.status_code pode ser útil (ex: 250 OK)
        return response.status_code in [250] # Simplificado, verificar códigos SMTP corretos
    except Exception as e:
        logger.error(f"Erro ao enviar email para {email_to}: {e}")
        return False

# --- Adicionar função específica para email de verificação ---
async def send_verification_email(email_to: str, verification_token: str) -> bool:
    project_name = "Sua Aplicação" # Ou buscar de settings
    subject = f"{project_name} - Verifique seu endereço de e-mail"
    verification_url = f"{settings.VERIFICATION_URL_BASE}/{verification_token}" # Monta a URL completa

    # Templates HTML e Texto simples (podem ser movidos para arquivos .html)
    html_content = f"""
    <html>
    <body>
        <p>Olá,</p>
        <p>Obrigado por se registrar em {project_name}. Por favor, clique no link abaixo para verificar seu e-mail:</p>
        <p><a href="{verification_url}">{verification_url}</a></p>
        <p>Se você não se registrou, por favor ignore este e-mail.</p>
        <p>Atenciosamente,<br>Equipe {project_name}</p>
    </body>
    </html>
    """

    return await send_email_async(
        email_to=email_to,
        subject_template=subject,
        html_template=html_content,
        environment={"project_name": project_name, "verification_url": verification_url}
    )

# Necessário para rodar message.send em executor
import asyncio