import os
import logging
from logging.handlers import RotatingFileHandler

# Define directories
LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logs')
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

# App Logger Setup
app_log_path = os.path.join(LOG_DIR, 'app.log')
app_logger = logging.getLogger('NetGuardApp')
app_logger.setLevel(logging.INFO)

# Avoid adding duplicate handlers if re-initialized
if not app_logger.handlers:
    # Rotate at 5MB, keep 3 backup logs
    app_handler = RotatingFileHandler(app_log_path, maxBytes=5 * 1024 * 1024, backupCount=3)
    app_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    app_handler.setFormatter(app_formatter)
    app_logger.addHandler(app_handler)

    # Console Handler for debugging
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(app_formatter)
    app_logger.addHandler(console_handler)

# Threat Logger Setup (specifically for threat detections)
threat_log_path = os.path.join(LOG_DIR, 'threat.log')
threat_logger = logging.getLogger('NetGuardThreats')
threat_logger.setLevel(logging.WARNING)

if not threat_logger.handlers:
    threat_handler = RotatingFileHandler(threat_log_path, maxBytes=5 * 1024 * 1024, backupCount=3)
    threat_formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')
    threat_handler.setFormatter(threat_formatter)
    threat_logger.addHandler(threat_handler)

def get_app_logger():
    return app_logger

def get_threat_logger():
    return threat_logger
