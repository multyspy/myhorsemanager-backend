Copia **TODO** este contenido y pégalo en el Bloc de notas:

```python
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import logging
from datetime import datetime
from typing import Optional, Dict, Any
from pathlib import Path
from dotenv import load_dotenv

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

SMTP_HOST = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
SMTP_USER = os.environ.get('SMTP_USER', '')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')
ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', '')

def create_metrics_html(metrics: Dict[str, Any]) -> str:
    db_status = metrics.get('limits', {}).get('mongodb_atlas', {})
    usage_percentage = db_status.get('usage_percentage', 0)
    status = db_status.get('status', 'ok')
    
    if status == 'critical':
        status_color = '#F44336'
        status_text = '🔴 CRITICO'
    elif status == 'warning':
        status_color = '#FF9800'
        status_text = '🟠 ADVERTENCIA'
    else:
        status_color = '#4CAF50'
        status_text = '🟢 OK'
    
    bar_width = min(usage_percentage, 100)
    collections = metrics.get('collections', {})
    collections_html = ''
    for name, data in sorted(collections.items(), key=lambda x: x[1].get('size_mb', 0), reverse=True):
        if name not in ['backups', 'backup_parts', 'metrics_history']:
            collections_html += f'<tr><td style="padding:8px;border-bottom:1px solid #eee;">{name}</td><td style="padding:8px;text-align:center;">{data.get("count", 0)}</td><td style="padding:8px;text-align:right;">{data.get("size_mb", 0)} MB</td></tr>'
    
    html = f'''<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;margin:0;padding:0;background:#f5f5f5;">
    <div style="max-width:600px;margin:0 auto;padding:20px;">
    <div style="background:linear-gradient(135deg,#2E7D32,#1B5E20);padding:30px;border-radius:12px 12px 0 0;text-align:center;">
    <h1 style="color:white;margin:0;">🐴 My Horse Manager</h1>
    <p style="color:rgba(255,255,255,0.9);margin:8px 0 0 0;">Informe Diario del Sistema</p></div>
    <div style="background:white;padding:24px;border-radius:0 0 12px 12px;">
    <p style="color:#666;text-align:center;">📅 {datetime.now().strftime('%d/%m/%Y %H:%M')}</p>
    <div style="background:#E8F5E9;padding:20px;border-radius:12px;text-align:center;margin-bottom:24px;">
    <h2 style="margin:0;color:{status_color};">{status_text}</h2></div>
    <h3>💾 Base de Datos (MongoDB Atlas)</h3>
    <div style="background:#f9f9f9;padding:16px;border-radius:8px;">
    <div style="display:flex;justify-content:space-between;margin-bottom:8px;">
    <span>Uso actual:</span><span style="font-size:24px;font-weight:bold;color:{status_color};">{usage_percentage}%</span></div>
    <div style="background:#e0e0e0;height:20px;border-radius:10px;overflow:hidden;">
    <div style="background:{status_color};height:100%;width:{bar_width}%;border-radius:10px;"></div></div>
    <div style="display:flex;justify-content:space-between;margin-top:8px;color:#666;">
    <span>{db_status.get('used_mb', 0)} MB usados</span><span>{db_status.get('limit_mb', 512)} MB limite</span></div></div>
    <h3>📊 Uso por Coleccion</h3>
    <table style="width:100%;border-collapse:collapse;">
    <thead><tr style="background:#f5f5f5;"><th style="padding:12px 8px;text-align:left;">Coleccion</th><th style="padding:12px 8px;text-align:center;">Docs</th><th style="padding:12px 8px;text-align:right;">Tamano</th></tr></thead>
    <tbody>{collections_html}</tbody></table>
    <p style="margin-top:32px;text-align:center;color:#999;font-size:12px;">Email automatico de My Horse Manager</p>
    </div></div></body></html>'''
    return html

def send_email(to_email: str, subject: str, html_content: str) -> bool:
    if not SMTP_USER or not SMTP_PASSWORD:
        logging.error("Email credentials not configured")
        return False
    try:
        message = MIMEMultipart("alternative")
        message["Subject"] = subject
        message["From"] = f"My Horse Manager <{SMTP_USER}>"
        message["To"] = to_email
        message.attach(MIMEText(html_content, "html"))
        context = ssl.create_default_context()
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls(context=context)
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, to_email, message.as_string())
        logging.info(f"Email sent successfully to {to_email}")
        return True
    except Exception as e:
        logging.error(f"Failed to send email: {str(e)}")
        return False

def send_daily_report(metrics: Dict[str, Any]) -> bool:
    if not ADMIN_EMAIL:
        return False
    subject = f"🐴 My Horse Manager - Informe Diario ({datetime.now().strftime('%d/%m/%Y')})"
    html_content = create_metrics_html(metrics)
    return send_email(ADMIN_EMAIL, subject, html_content)

def send_alert_email(alert_type: str, service: str, message: str, metrics: Dict[str, Any]) -> bool:
    if not ADMIN_EMAIL:
        return False
    subject = f"🔴 ALERTA - {service}" if alert_type == 'critical' else f"⚠️ ADVERTENCIA - {service}"
    html = f'<html><body><h1 style="color:#F44336;">{subject}</h1><p style="font-size:18px;">{message}</p><p>Fecha: {datetime.now().strftime("%d/%m/%Y %H:%M")}</p></body></html>'
    return send_email(ADMIN_EMAIL, subject, html)
```

