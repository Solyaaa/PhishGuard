
import json
from bson import ObjectId
from datetime import datetime


class JSONEncoder(json.JSONEncoder):
    """
    Розширений JSON енкодер для правильної серіалізації ObjectId та datetime.
    """

    def default(self, obj):
        if isinstance(obj, ObjectId):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


def sanitize_url(url):
    """
    Очищує та нормалізує URL.

    Args:
        url (str): Вхідний URL

    Returns:
        str: Очищений URL
    """
    url = url.strip()

    # Додавання протоколу, якщо його немає
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    return url


def get_domain_from_url(url):
    """
    Витягує домен з URL.

    Args:
        url (str): Вхідний URL

    Returns:
        str: Домен (без протоколу та шляху)
    """
    from urllib.parse import urlparse
    parsed_url = urlparse(url)
    return parsed_url.netloc


def calculate_risk_score(checks):
    """
    Обчислює загальний показник ризику на основі всіх перевірок.

    Args:
        checks (list): Список результатів перевірок

    Returns:
        int: Загальний показник від 0 до 100
    """
    if not checks:
        return 50  # Середній показник за замовчуванням

    total_weight = sum(check.get('weight', 1) for check in checks)
    weighted_score = sum(
        check.get('score', 0) * check.get('weight', 1)
        for check in checks
    )

    # Інвертуємо показник, оскільки нижчий показник ризику = вища безпека
    return round(100 - (weighted_score / total_weight) if total_weight > 0 else 50)


def is_valid_mongodb_id(id_str):
    """
    Перевіряє, чи рядок є валідним ObjectId.

    Args:
        id_str (str): Рядок для перевірки

    Returns:
        bool: True, якщо це валідний ObjectId
    """
    try:
        ObjectId(id_str)
        return True
    except:
        return False


