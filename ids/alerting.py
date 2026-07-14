import os
import smtplib
from email.message import EmailMessage
import requests
import logging

logger = logging.getLogger(__name__)

def send_alert(src_ip, attack_type, packet_count):
    subject = f"IDS Alert: {attack_type} detected from {src_ip}"
    body = f"Detected {attack_type} from {src_ip}. Packet count: {packet_count}."
    
    send_email(subject, body)
    send_discord_webhook(subject, body)

def send_email(subject, body):
    smtp_user = os.environ.get('SMTP_USER')
    smtp_pass = os.environ.get('SMTP_PASS')
    smtp_server = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    smtp_port = int(os.environ.get('SMTP_PORT', '587'))
    to_email = os.environ.get('ALERT_EMAIL')

    if not all([smtp_user, smtp_pass, to_email]):
        logger.warning("SMTP credentials not fully configured. Skipping email alert.")
        return

    try:
        msg = EmailMessage()
        msg.set_content(body)
        msg['Subject'] = subject
        msg['From'] = smtp_user
        msg['To'] = to_email

        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
    except Exception as e:
        logger.error(f"Failed to send email alert: {e}")

def send_discord_webhook(subject, body):
    webhook_url = os.environ.get('DISCORD_WEBHOOK_URL')
    
    if not webhook_url:
        logger.warning("Discord webhook URL not configured. Skipping Discord alert.")
        return
    
    data = {
        "content": f"**{subject}**\n{body}"
    }
    
    try:
        response = requests.post(webhook_url, json=data)
        response.raise_for_status()
    except Exception as e:
        logger.error(f"Failed to send Discord webhook: {e}")
