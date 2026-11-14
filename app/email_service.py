import os
import smtplib
from email.message import EmailMessage


def send_verification_email(recipient, token):
    host = os.getenv("AGENTGUARD_SMTP_HOST")
    port = int(os.getenv("AGENTGUARD_SMTP_PORT", "587"))
    username = os.getenv("AGENTGUARD_SMTP_USERNAME")
    password = os.getenv("AGENTGUARD_SMTP_PASSWORD")
    sender = os.getenv("AGENTGUARD_SMTP_FROM")
    public_url = os.getenv(
        "AGENTGUARD_PUBLIC_URL",
        "http://127.0.0.1:8000"
    )

    if not all([host, username, password, sender]):
        raise RuntimeError(
            "Email delivery is not configured."
        )

    message = EmailMessage()
    message["Subject"] = "Verify your AgentGuard AI account"
    message["From"] = sender
    message["To"] = recipient

    message.set_content(
        "Welcome to AgentGuard AI!\n\n"
        "Use the verification token below to verify your account:\n\n"
        f"{token}\n\n"
        "This token expires after 30 minutes.\n\n"
        f"AgentGuard AI: {public_url}"
    )

    if port == 465:
        with smtplib.SMTP_SSL(host, port, timeout=15) as server:
            server.login(username, password)
            server.send_message(message)
    else:
        with smtplib.SMTP(host, port, timeout=15) as server:
            server.starttls()
            server.login(username, password)
            server.send_message(message)

    return True


def send_approval_key_recovery_email(recipient, token):
    host = os.getenv("AGENTGUARD_SMTP_HOST")
    port = int(os.getenv("AGENTGUARD_SMTP_PORT", "587"))
    username = os.getenv("AGENTGUARD_SMTP_USERNAME")
    password = os.getenv("AGENTGUARD_SMTP_PASSWORD")
    sender = os.getenv("AGENTGUARD_SMTP_FROM")
    public_url = os.getenv("AGENTGUARD_PUBLIC_URL", "http://127.0.0.1:8000")
    if not all([host, username, password, sender]):
        raise RuntimeError("Email delivery is not configured.")
    message = EmailMessage()
    message["Subject"] = "AgentGuard AI Approval Key recovery"
    message["From"] = sender
    message["To"] = recipient
    message.set_content(
        "A request was made to replace your AgentGuard AI Approval Key.\n\n"
        "Use this one-time recovery token in the Approval Key recovery form:\n\n"
        f"{token}\n\nThis token expires after 30 minutes. "
        "If you did not request this, ignore this email.\n\n" + public_url
    )
    if port == 465:
        with smtplib.SMTP_SSL(host, port, timeout=15) as server:
            server.login(username, password)
            server.send_message(message)
    else:
        with smtplib.SMTP(host, port, timeout=15) as server:
            server.starttls()
            server.login(username, password)
            server.send_message(message)
    return True
