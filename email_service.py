import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
import os
import logging
from datetime import datetime
from typing import Optional, Dict, Any, List
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# Email configuration
SMTP_HOST = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
SMTP_USER = os.environ.get('SMTP_USER', '')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')
ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', '')

def create_metrics_html(metrics: Dict[str, Any]) -> str:
    """Create HTML email content with metrics"""
    
    # Get status colors
    db_status = metrics.get('limits', {}).get('mongodb_atlas', {})
    usage_percentage = db_status.get('usage_percentage', 0)
    status = db_status.get('status', 'ok')
    
    if status == 'critical':
        status_color = '#F44336'
        status_text = '🔴 CRÍTICO'
        status_bg = '#FFEBEE'
    elif status == 'warning':
        status_color = '#FF9800'
        status_text = '🟠 ADVERTENCIA'
        status_bg = '#FFF3E0'
    else:
        status_color = '#4CAF50'
        status_text = '🟢 OK'
        status_bg = '#E8F5E9'
    
    # Calculate bar width
    bar_width = min(usage_percentage, 100)
    
    # Get collections data
    collections = metrics.get('collections', {})
    collections_html = ''
    for name, data in sorted(collections.items(), key=lambda x: x[1].get('size_mb', 0), reverse=True):
        if name not in ['backups', 'backup_parts', 'metrics_history']:
            collections_html += f'''
            <tr>
                <td style="padding: 8px; border-bottom: 1px solid #eee; text-transform: capitalize;">{name}</td>
                <td style="padding: 8px; border-bottom: 1px solid #eee; text-align: center;">{data.get('count', 0)}</td>
                <td style="padding: 8px; border-bottom: 1px solid #eee; text-align: right; font-weight: 500;">{data.get('size_mb', 0)} MB</td>
            </tr>
            '''
    
    # Get alerts
    alerts_html = ''
    for alert in metrics.get('alerts', []):
        alert_bg = '#FFEBEE' if alert['type'] == 'critical' else '#FFF3E0'
        alert_icon = '🔴' if alert['type'] == 'critical' else '🟠'
        alerts_html += f'''
        <div style="background: {alert_bg}; padding: 12px; border-radius: 8px; margin-bottom: 8px; border-left: 4px solid {status_color};">
            <strong>{alert_icon} {alert['service']}</strong><br>
            <span style="color: #666;">{alert['message']}</span>
        </div>
        '''
    
    if not alerts_html:
        alerts_html = '<p style="color: #4CAF50;">✅ No hay alertas. Todo funciona correctamente.</p>'
    
    # Last backup info
    backup_info = metrics.get('storage', {}).get('backups', {})
    last_backup = backup_info.get('last_backup')
    if last_backup:
        try:
            backup_date = datetime.fromisoformat(last_backup.replace('Z', '+00:00'))
            backup_str = backup_date.strftime('%d/%m/%Y %H:%M')
        except:
            backup_str = last_backup
        backup_type = '⏰ Automático' if backup_info.get('last_backup_type') == 'automatic' else '✋ Manual'
    else:
        backup_str = 'No hay backups'
        backup_type = '-'
    
    html = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
    </head>
    <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 0; background-color: #f5f5f5;">
        <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
            <!-- Header -->
            <div style="background: linear-gradient(135deg, #2E7D32 0%, #1B5E20 100%); padding: 30px; border-radius: 12px 12px 0 0; text-align: center;">
                <h1 style="color: white; margin: 0; font-size: 24px;">🐴 My Horse Manager</h1>
                <p style="color: rgba(255,255,255,0.9); margin: 8px 0 0 0;">Informe Diario del Sistema</p>
            </div>
            
            <!-- Main Content -->
            <div style="background: white; padding: 24px; border-radius: 0 0 12px 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                
                <!-- Date -->
                <p style="color: #666; text-align: center; margin-bottom: 24px;">
                    📅 {datetime.now().strftime('%d de %B de %Y, %H:%M')}
                </p>
                
                <!-- Status Badge -->
                <div style="background: {status_bg}; padding: 20px; border-radius: 12px; text-align: center; margin-bottom: 24px;">
                    <h2 style="margin: 0; color: {status_color}; font-size: 28px;">{status_text}</h2>
                    <p style="margin: 8px 0 0 0; color: #666;">Estado General del Sistema</p>
                </div>
                
                <!-- Alerts Section -->
                <h3 style="color: #333; border-bottom: 2px solid #eee; padding-bottom: 8px;">⚠️ Alertas</h3>
                {alerts_html}
                
                <!-- MongoDB Usage -->
                <h3 style="color: #333; border-bottom: 2px solid #eee; padding-bottom: 8px; margin-top: 24px;">💾 Base de Datos (MongoDB Atlas)</h3>
                <div style="background: #f9f9f9; padding: 16px; border-radius: 8px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                        <span style="color: #666;">Uso actual:</span>
                        <span style="font-size: 24px; font-weight: bold; color: {status_color};">{usage_percentage}%</span>
                    </div>
                    <!-- Progress Bar -->
                    <div style="background: #e0e0e0; height: 20px; border-radius: 10px; overflow: hidden;">
                        <div style="background: {status_color}; height: 100%; width: {bar_width}%; border-radius: 10px;"></div>
                    </div>
                    <div style="display: flex; justify-content: space-between; margin-top: 8px; color: #666; font-size: 14px;">
                        <span>{db_status.get('used_mb', 0)} MB usados</span>
                        <span>{db_status.get('limit_mb', 512)} MB límite</span>
                    </div>
                </div>
                
                <!-- Collections Table -->
                <h3 style="color: #333; border-bottom: 2px solid #eee; padding-bottom: 8px; margin-top: 24px;">📊 Uso por Colección</h3>
                <table style="width: 100%; border-collapse: collapse;">
                    <thead>
                        <tr style="background: #f5f5f5;">
                            <th style="padding: 12px 8px; text-align: left; font-weight: 600;">Colección</th>
                            <th style="padding: 12px 8px; text-align: center; font-weight: 600;">Documentos</th>
                            <th style="padding: 12px 8px; text-align: right; font-weight: 600;">Tamaño</th>
                        </tr>
                    </thead>
                    <tbody>
                        {collections_html}
                    </tbody>
                </table>
                
                <!-- Backup Info -->
                <h3 style="color: #333; border-bottom: 2px solid #eee; padding-bottom: 8px; margin-top: 24px;">🔄 Último Backup</h3>
                <div style="background: #f9f9f9; padding: 16px; border-radius: 8px;">
                    <p style="margin: 0;"><strong>Fecha:</strong> {backup_str}</p>
                    <p style="margin: 8px 0 0 0;"><strong>Tipo:</strong> {backup_type}</p>
                </div>
                
                <!-- Footer -->
                <div style="margin-top: 32px; padding-top: 16px; border-top: 1px solid #eee; text-align: center; color: #999; font-size: 12px;">
                    <p>Este es un correo automático enviado por My Horse Manager.</p>
                    <p>Siguiente backup programado: 3:00 AM (hora de España)</p>
                </div>
            </div>
        </div>
    </body>
    </html>
    '''
    
    return html


def send_email(
    to_email: str,
    subject: str,
    html_content: str,
    text_content: Optional[str] = None
) -> bool:
    """Send an email using SMTP"""
    
    if not SMTP_USER or not SMTP_PASSWORD:
        logging.error("Email credentials not configured")
        return False
    
    try:
        # Create message
        message = MIMEMultipart("alternative")
        message["Subject"] = subject
        message["From"] = f"My Horse Manager <{SMTP_USER}>"
        message["To"] = to_email
        
        # Add plain text version if provided
        if text_content:
            part1 = MIMEText(text_content, "plain")
            message.attach(part1)
        
        # Add HTML version
        part2 = MIMEText(html_content, "html")
        message.attach(part2)
        
        # Create secure connection and send
        context = ssl.create_default_context()
        
        # Try SSL first (port 465), fallback to STARTTLS (port 587)
        try:
            if SMTP_PORT == 465:
                with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context) as server:
                    server.login(SMTP_USER, SMTP_PASSWORD)
                    server.sendmail(SMTP_USER, to_email, message.as_string())
            else:
                with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
                    server.starttls(context=context)
                    server.login(SMTP_USER, SMTP_PASSWORD)
                    server.sendmail(SMTP_USER, to_email, message.as_string())
        except OSError as e:
            # If STARTTLS fails, try SSL on port 465
            logging.warning(f"STARTTLS failed, trying SSL: {e}")
            with smtplib.SMTP_SSL(SMTP_HOST, 465, context=context) as server:
                server.login(SMTP_USER, SMTP_PASSWORD)
                server.sendmail(SMTP_USER, to_email, message.as_string())
        
        logging.info(f"Email sent successfully to {to_email}")
        return True
        
    except Exception as e:
        logging.error(f"Failed to send email: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


def send_daily_report(metrics: Dict[str, Any]) -> bool:
    """Send daily metrics report email"""
    
    if not ADMIN_EMAIL:
        logging.error("Admin email not configured")
        return False
    
    subject = f"🐴 My Horse Manager - Informe Diario ({datetime.now().strftime('%d/%m/%Y')})"
    
    # Check if there are critical alerts
    alerts = metrics.get('alerts', [])
    critical_alerts = [a for a in alerts if a.get('type') == 'critical']
    if critical_alerts:
        subject = f"🔴 ALERTA CRÍTICA - {subject}"
    elif alerts:
        subject = f"⚠️ {subject}"
    
    html_content = create_metrics_html(metrics)
    
    return send_email(ADMIN_EMAIL, subject, html_content)


def send_alert_email(alert_type: str, service: str, message: str, metrics: Dict[str, Any]) -> bool:
    """Send immediate alert email"""
    
    if not ADMIN_EMAIL:
        logging.error("Admin email not configured")
        return False
    
    if alert_type == 'critical':
        subject = f"🔴 ALERTA CRÍTICA - {service}"
        icon = '🔴'
    else:
        subject = f"⚠️ ADVERTENCIA - {service}"
        icon = '🟠'
    
    html_content = f'''
    <!DOCTYPE html>
    <html>
    <head><meta charset="UTF-8"></head>
    <body style="font-family: Arial, sans-serif; padding: 20px;">
        <div style="max-width: 500px; margin: 0 auto;">
            <h1 style="color: {'#F44336' if alert_type == 'critical' else '#FF9800'};">
                {icon} {subject}
            </h1>
            <div style="background: {'#FFEBEE' if alert_type == 'critical' else '#FFF3E0'}; padding: 20px; border-radius: 8px; margin: 20px 0;">
                <p style="font-size: 18px; margin: 0;">{message}</p>
            </div>
            <p style="color: #666;">
                Fecha: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}<br>
                Servicio: {service}
            </p>
            <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
            <p style="color: #999; font-size: 12px;">
                Este es un correo automático de alerta de My Horse Manager.
            </p>
        </div>
    </body>
    </html>
    '''
    
    return send_email(ADMIN_EMAIL, subject, html_content)
