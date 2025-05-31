import os
import logging
from dotenv import load_dotenv

load_dotenv()

DEBUG = os.getenv('DEBUG', 'False').lower() in ('true', '1', 't')
PORT = int(os.getenv('PORT', 5000))
ENVIRONMENT = os.getenv('ENVIRONMENT', 'production')

MONGO_URI = os.getenv('MONGO_URI')

SECRET_KEY = os.getenv('SECRET_KEY', 'change-me-in-production')
ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')

# GOOGLE_SAFE_BROWSING_API_KEY = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY', '') # Якщо не використовуєте, можна видалити
# PHISHTANK_API_KEY = os.getenv('PHISHTANK_API_KEY', '') # Якщо не використовуєте, можна видалити
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '') # <-- Залишити лише це визначення і додати порожній рядок як default

LOG_LEVEL = getattr(logging, os.getenv('LOG_LEVEL', 'INFO').upper(), logging.INFO)
LOG_DIR = os.getenv('LOG_DIR', 'logs')

# Кеш
CACHE_ENABLED = os.getenv('CACHE_ENABLED', 'True').lower() in ('true', '1', 't')
CACHE_TTL = int(os.getenv('CACHE_TTL', 3600))
CACHE_TYPE = os.getenv('CACHE_TYPE', 'redis')
CACHE_REDIS_URL = os.getenv('CACHE_REDIS_URL', 'redis://localhost:6379/0')

# Rate limiting
RATE_LIMIT_ENABLED = os.getenv('RATE_LIMIT_ENABLED', 'True').lower() in ('true', '1', 't')
RATE_LIMIT_PER_MINUTE = int(os.getenv('RATE_LIMIT_PER_MINUTE', 60))
RATE_LIMIT_STORAGE_URL = os.getenv('RATE_LIMIT_STORAGE_URL', 'redis://localhost:6379/1')

# Перейменовані пороги для ясності (як ми домовлялися в phish_detector.py)
PHISHING_THRESHOLD_SCORE = int(os.getenv('PHISHING_THRESHOLD_SCORE', 150)) # Нова назва
WARNING_THRESHOLD_SCORE = int(os.getenv('WARNING_THRESHOLD_SCORE', 50))   # Нова назва

REQUEST_TIMEOUT = int(os.getenv('REQUEST_TIMEOUT', 10))
USER_AGENT = os.getenv('USER_AGENT', 'PhishGuard/1.0')

BLACKLISTS = [
    'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt',
    'https://urlhaus.abuse.ch/downloads/text_recent/'
]

extra_blacklists = os.getenv('BLACKLISTS_EXTRA', '')
if extra_blacklists:
    BLACKLISTS += [url.strip() for url in extra_blacklists.split(',') if url.strip()]

def setup_logging():
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)

    log_format = '%(asctime)s - %(levelname)s - %(name)s - %(message)s'

    file_handler = logging.FileHandler(os.path.join(LOG_DIR, 'phishguard.log'))
    file_handler.setFormatter(logging.Formatter(log_format))

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(log_format))

    root_logger = logging.getLogger()
    root_logger.setLevel(LOG_LEVEL)
    root_logger.handlers.clear()
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)

    return root_logger