
import os
from dotenv import load_dotenv
import logging

# Завантаження змінних середовища
load_dotenv()

# Основні налаштування
DEBUG = os.getenv('DEBUG', 'False').lower() in ('true', '1', 't')
PORT = int(os.getenv('PORT', 5000))
ENVIRONMENT = os.getenv('ENVIRONMENT', 'production')

# MongoDB налаштування
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/phishguard')
MONGO_USERNAME = os.getenv('MONGO_USERNAME', '')
MONGO_PASSWORD = os.getenv('MONGO_PASSWORD', '')

# Налаштування безпеки
SECRET_KEY = os.getenv('SECRET_KEY', 'default-insecure-key')
ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')

# Налаштування API-ключів для зовнішніх сервісів
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY', '')
PHISHTANK_API_KEY = os.getenv('PHISHTANK_API_KEY', '')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')

# Налаштування логування
LOG_LEVEL = getattr(logging, os.getenv('LOG_LEVEL', 'INFO'))
LOG_DIR = os.getenv('LOG_DIR', 'logs')

# Налаштування кешування
CACHE_ENABLED = os.getenv('CACHE_ENABLED', 'True').lower() in ('true', '1', 't')
CACHE_TTL = int(os.getenv('CACHE_TTL', 3600))

# Налаштування обмеження запитів
RATE_LIMIT_ENABLED = os.getenv('RATE_LIMIT_ENABLED', 'True').lower() in ('true', '1', 't')
RATE_LIMIT_PER_MINUTE = int(os.getenv('RATE_LIMIT_PER_MINUTE', 60))

# Налаштування для виявлення фішингу
PHISHING_THRESHOLD = 65
WARNING_THRESHOLD = 40

# Налаштування для HTTP-запитів
REQUEST_TIMEOUT = 10
USER_AGENT = 'PhishGuard/1.0'

# Налаштування для чорних списків
BLACKLISTS = [
    'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt',
    # Додайте інші джерела чорних списків тут
]


# Функція для налаштування логування
def setup_logging():
    """Налаштовує систему логування."""

    # Створення директорії для логів, якщо її не існує
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)

    # Формат логування
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    # Налаштування логування в файл
    file_handler = logging.FileHandler(f'{LOG_DIR}/phishguard.log')
    file_handler.setFormatter(logging.Formatter(log_format))

    # Налаштування виводу в консоль
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(log_format))

    # Налаштування кореневого логера
    root_logger = logging.getLogger()
    root_logger.setLevel(LOG_LEVEL)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    # Зниження рівня логування для деяких бібліотек
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)

    return root_logger


