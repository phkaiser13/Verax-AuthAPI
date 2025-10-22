# auth_api/app/services/email_service.py
import emails
from emails.template import JinjaTemplate
from app.core.config import settings
from loguru import logger
from typing import Dict, Any
import asyncio  # Importação no topo
import traceback # Importação para log completo

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

    logger.debug(f"Tentando conectar ao SMTP: {smtp_options.get('host')}:{smtp_options.get('port')}")
    logger.debug(f"Opções SMTP: {smtp_options}")

    try:
        # A biblioteca 'emails' não é nativamente async, rodamos em thread separada
        loop = asyncio.get_running_loop()
        response = await loop.run_in_executor(
            None, # Usa o executor de thread padrão
            message.send, # Função a ser executada
            email_to, # Argumentos para message.send
            smtp_options
        )
        
        # --- LOG DE DEBUG MELHORADO ---
        if response:
            logger.info(f"Resposta completa do SMTP: {response.__dict__}")
            logger.info(f"Email enviado para {email_to}, Assunto: {subject_template}. Resposta SMTP (status_code): {response.status_code}")
            # Verifica se a resposta foi bem-sucedida
            return response.status_code in [250, 252] # 250 OK, 252 Cannot VRFY
        else:
            logger.warning(f"Falha ao enviar email para {email_to}. A resposta do SMTP foi 'None' ou vazia.")
            return False
        # --- FIM DO LOG DE DEBUG ---

    except Exception as e:
        logger.error(f"Erro CRÍTICO ao enviar email para {email_to}: {e}")
        logger.error(f"Traceback completo: {traceback.format_exc()}")
        return False

# --- Função específica para email de verificação ---
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

# --- Função específica para email de reset de senha ---
async def send_password_reset_email(email_to: str, reset_token: str) -> bool:
    project_name = "Sua Aplicação" # Ou buscar de settings
    subject = f"{project_name} - Redefinição de Senha"
    reset_url = f"{settings.RESET_PASSWORD_URL_BASE}/{reset_token}" # Monta a URL completa

    # Templates HTML e Texto simples
    html_content = f"""
    <html>
    <body>
        <p>Olá,</p>
        <p>Recebemos uma solicitação para redefinir sua senha em {project_name}.</p>
        <p>Se foi você, clique no link abaixo para criar uma nova senha:</p>
        <p><a href="{reset_url}">{reset_url}</a></p>
        <p>Este link expirará em {settings.RESET_PASSWORD_TOKEN_EXPIRE_MINUTES} minutos.</p>
        <p>Se você não solicitou uma redefinição de senha, por favor ignore este e-mail.</p>
        <p>Atenciosamente,<br>Equipe {project_name}</p>
    </body>
    </html>
    """

    return await send_email_async(
        email_to=email_to,
        subject_template=subject,
        html_template=html_content,
        environment={"project_name": project_name, "reset_url": reset_url}
    )

