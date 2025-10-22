# auth_api/app/services/email_service.py
import asyncio
import traceback
from typing import Dict, Any
from loguru import logger
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, From, To, Content
from app.core.config import settings

# Helper assíncrono para a biblioteca 'sendgrid' (que é síncrona)
async def send_email_http_api(
    email_to: str,
    subject: str,
    html_content: str
) -> bool:
    """
    Envia um email usando a API HTTP do SendGrid de forma assíncrona.
    """
    if not settings.SENDGRID_API_KEY:
        logger.error("SENDGRID_API_KEY não está configurada. Email não será enviado.")
        return False

    message = Mail(
        from_email=From(settings.EMAIL_FROM, settings.EMAIL_FROM_NAME),
        to_emails=To(email_to),
        subject=subject,
        html_content=Content("text/html", html_content)
    )

    try:
        sg = SendGridAPIClient(settings.SENDGRID_API_KEY)
        
        # A biblioteca 'sendgrid' é bloqueante (IO-bound)
        # Rodamos em um executor de thread separado para não bloquear o loop de eventos
        loop = asyncio.get_running_loop()
        response = await loop.run_in_executor(
            None,  # Usa o executor de thread padrão
            sg.send,
            message
        )

        status_code = response.status_code
        if 200 <= status_code < 300:
            logger.info(f"Email enviado com sucesso para {email_to} via SendGrid. Status: {status_code}")
            return True
        else:
            logger.error(f"Falha ao enviar email para {email_to} via SendGrid.")
            logger.error(f"Status: {status_code}")
            logger.error(f"Body: {response.body}")
            logger.error(f"Headers: {response.headers}")
            return False

    except Exception as e:
        logger.error(f"Erro CRÍTICO ao enviar email para {email_to} com SendGrid: {e}")
        logger.error(f"Traceback completo: {traceback.format_exc()}")
        return False

# --- Função específica para email de verificação ---
async def send_verification_email(email_to: str, verification_token: str) -> bool:
    project_name = settings.EMAIL_FROM_NAME or "Sua Aplicação"
    subject = f"{project_name} - Verifique seu endereço de e-mail"
    verification_url = f"{settings.VERIFICATION_URL_BASE}/{verification_token}"

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

    return await send_email_http_api(
        email_to=email_to,
        subject=subject,
        html_content=html_content
    )

# --- Função específica para email de reset de senha ---
async def send_password_reset_email(email_to: str, reset_token: str) -> bool:
    project_name = settings.EMAIL_FROM_NAME or "Sua Aplicação"
    subject = f"{project_name} - Redefinição de Senha"
    reset_url = f"{settings.RESET_PASSWORD_URL_BASE}/{reset_token}"

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

    return await send_email_http_api(
        email_to=email_to,
        subject=subject,
        html_content=html_content
    )