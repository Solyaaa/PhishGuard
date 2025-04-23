import re
import ssl
import socket
import whois
import requests
import tldextract
import dns.resolver
from urllib.parse import urlparse
from datetime import datetime, timedelta
from bs4 import BeautifulSoup
import concurrent.futures
import logging
from typing import Dict, List, Any, Union
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import os
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PhishDetector:
    """
    Клас для виявлення фішингових URL за допомогою різних методів.
    """

    def __init__(self):
        """Ініціалізує PhishDetector з необхідними конфігураціями."""
        self.phishing_threshold = 65
        self.warning_threshold = 40
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        self.timeout = 10  # секунд

        # Зменшення кількості джерел чорних списків або вибір менших за розміром
        self.blacklists = [
            'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt',
        ]

        # Використання кешування файлів для чорного списку
        cache_file = "blacklist_cache.txt"
        self.blacklist_domains = self._load_blacklists_with_cache(cache_file)

    def _load_blacklists_with_cache(self, cache_file, cache_ttl=86400) -> set:
        """Завантажує чорні списки з файлу кешу або з джерел."""
        domains = set()

        # Перевірка наявності та актуальності кешу
        try:
            if os.path.exists(cache_file):
                # Перевірка часу останньої модифікації
                file_time = os.path.getmtime(cache_file)
                if (time.time() - file_time) < cache_ttl:  # Кеш дійсний 24 години
                    with open(cache_file, 'r') as f:
                        domains = set(line.strip() for line in f if line.strip())
                    logger.info(f"Завантажено {len(domains)} доменів з кешу")
                    return domains
        except Exception as e:
            logger.error(f"Помилка перевірки кешу: {str(e)}")

        # Якщо кеш відсутній або застарілий, завантажуємо з джерел
        for url in self.blacklists:
            try:
                response = requests.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    new_domains = set(response.text.splitlines())
                    domains.update(new_domains)
                    logger.info(f"Завантажено {len(new_domains)} доменів з {url}")
            except Exception as e:
                logger.error(f"Помилка завантаження чорного списку з {url}: {str(e)}")

        # Зберігаємо в кеш
        try:
            with open(cache_file, 'w') as f:
                for domain in domains:
                    f.write(domain + '\n')
            logger.info(f"Збережено {len(domains)} доменів у кеш")
        except Exception as e:
            logger.error(f"Помилка збереження кешу: {str(e)}")

        return domains

    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Аналізує URL на наявність ознак фішингу.
        """
        # Очищення та нормалізація URL
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        # Парсинг URL
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"

        # Ініціалізація структури результату
        result = {
            'url': url,
            'domain': domain,
            'checks': [],
            'is_phishing': False,
            'final_score': 0,
            'scan_time': datetime.utcnow().isoformat()
        }

        # Швидка перевірка чорного списку (до запуску інших перевірок)
        if domain in self.blacklist_domains:
            result['checks'].append({
                'description': 'Чорний список',
                'details': 'Домен знайдено у чорних списках фішингу',
                'result': 'fail',
                'score': 100,
                'weight': 4
            })
            result['final_score'] = 0  # Найнижчий показник безпеки
            result['is_phishing'] = True
            return result

        # Запуск інших перевірок паралельно
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            url_check_task = executor.submit(self.check_url_structure, url)
            domain_check_task = executor.submit(self.check_domain_age_and_info, domain)
            ssl_check_task = executor.submit(self.check_ssl_certificate, url)
            content_check_task = executor.submit(self.check_page_content, url)

            # Збір результатів
            result['checks'].extend(url_check_task.result())
            result['checks'].extend(domain_check_task.result())
            result['checks'].extend(ssl_check_task.result())
            result['checks'].extend(content_check_task.result())

        # Обчислення фінального показника
        total_weight = sum(check.get('weight', 1) for check in result['checks'])
        weighted_score = sum(
            check.get('score', 0) * check.get('weight', 1)
            for check in result['checks']
        )

        if total_weight > 0:
            result['final_score'] = round(100 - (weighted_score / total_weight))
        else:
            result['final_score'] = 50  # Середній показник за замовчуванням

        # Визначення, чи URL є фішинговим
        result['is_phishing'] = result['final_score'] < self.phishing_threshold

        return result

    def check_ssl_certificate(self, url: str) -> List[Dict[str, Any]]:
        """Перевіряє SSL-сертифікат сайту."""
        checks = []

        if not url.startswith('https://'):
            checks.append({
                'description': 'SSL-сертифікат',
                'details': 'Сайт не використовує HTTPS',
                'result': 'fail',
                'score': 80,
                'weight': 3
            })
            return checks

        try:
            hostname = urlparse(url).netloc
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

                    # Перевірка терміну дії сертифіката
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days

                    if days_until_expiry < 0:
                        checks.append({
                            'description': 'SSL-сертифікат',
                            'details': 'Термін дії сертифіката закінчився',
                            'result': 'fail',
                            'score': 100,
                            'weight': 3
                        })
                    elif days_until_expiry < 30:
                        checks.append({
                            'description': 'SSL-сертифікат',
                            'details': f'Сертифікат закінчується через {days_until_expiry} днів',
                            'result': 'warning',
                            'score': 60,
                            'weight': 3
                        })
                    else:
                        checks.append({
                            'description': 'SSL-сертифікат',
                            'details': 'Дійсний SSL-сертифікат',
                            'result': 'pass',
                            'score': 0,
                            'weight': 3
                        })

                    # Перевірка видавця сертифіката
                    issuer = dict(x[0] for x in cert['issuer'])
                    organization = issuer.get('organizationName', '')

                    # Безкоштовні/дешеві сертифікати можуть бути підозрілими
                    free_issuers = ['Let\'s Encrypt', 'ZeroSSL']
                    if any(issuer in organization for issuer in free_issuers):
                        checks.append({
                            'description': 'Видавець сертифіката',
                            'details': f'Сертифікат виданий {organization}',
                            'result': 'warning',
                            'score': 20,
                            'weight': 1
                        })
                    else:
                        checks.append({
                            'description': 'Видавець сертифіката',
                            'details': f'Сертифікат виданий {organization}',
                            'result': 'pass',
                            'score': 0,
                            'weight': 1
                        })

        except Exception as e:
            checks.append({
                'description': 'SSL-сертифікат',
                'details': f'Помилка перевірки SSL-сертифіката: {str(e)}',
                'result': 'fail',
                'score': 80,
                'weight': 3
            })

        return checks

    def check_url_structure(self, url: str) -> List[Dict[str, Any]]:
        """Перевіряє структуру URL на наявність фішингових ознак."""
        checks = []

        # Перевірка наявності підозрілих слів у структурі URL
        suspicious_keywords = ['secure', 'account', 'signin', 'update', 'login', 'bank', 'pay', 'verify', 'verifyemail']
        for keyword in suspicious_keywords:
            if keyword in url.lower():
                checks.append({
                    'description': 'Структура URL',
                    'details': f'URL містить підозріле слово "{keyword}"',
                    'result': 'warning',
                    'score': 50,
                    'weight': 2
                })

        # Перевірка на довжину URL (надто довгі URL можуть бути підозрілими)
        if len(url) > 100:
            checks.append({
                'description': 'Структура URL',
                'details': 'URL надто довгий',
                'result': 'warning',
                'score': 60,
                'weight': 2
            })

        return checks

    def check_domain_age_and_info(self, domain: str) -> List[Dict[str, Any]]:
        """Перевіряє вік домену та інформацію про реєстратора."""
        checks = []

        try:
            # Отримання інформації WHOIS
            whois_info = whois.whois(domain)

            # Перевірка дати реєстрації домену
            if whois_info.creation_date:
                creation_date = whois_info.creation_date[0] if isinstance(whois_info.creation_date, list) else whois_info.creation_date
                age = (datetime.now() - creation_date).days
                if age < 30:  # Якщо домен новий
                    checks.append({
                        'description': 'Вік домену',
                        'details': f'Домен створений {age} днів тому',
                        'result': 'warning',
                        'score': 70,
                        'weight': 3
                    })
                else:
                    checks.append({
                        'description': 'Вік домену',
                        'details': f'Домен старший за 30 днів',
                        'result': 'pass',
                        'score': 0,
                        'weight': 3
                    })
            else:
                checks.append({
                    'description': 'Вік домену',
                    'details': 'Не вдалося отримати інформацію про реєстрацію домену',
                    'result': 'fail',
                    'score': 80,
                    'weight': 3
                })
        except Exception as e:
            checks.append({
                'description': 'Вік домену',
                'details': f'Помилка перевірки WHOIS: {str(e)}',
                'result': 'fail',
                'score': 80,
                'weight': 3
            })

        return checks

    def check_page_content(self, url: str) -> List[Dict[str, Any]]:
        """Перевіряє контент сторінки на підозрілі ознаки."""
        checks = []

        try:
            response = requests.get(url, headers={'User-Agent': self.user_agent}, timeout=self.timeout, verify=False)

            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')

                # Пошук підозрілих елементів у контенті (наприклад, схожих на фішингові форми)
                suspicious_form_keywords = ['password', 'confirm', 'credit', 'card', 'pin']
                for keyword in suspicious_form_keywords:
                    if keyword in soup.get_text().lower():
                        checks.append({
                            'description': 'Контент сторінки',
                            'details': f'Сторінка містить підозріле слово "{keyword}"',
                            'result': 'warning',
                            'score': 60,
                            'weight': 2
                        })

        except Exception as e:
            checks.append({
                'description': 'Контент сторінки',
                'details': f'Помилка завантаження сторінки: {str(e)}',
                'result': 'fail',
                'score': 70,
                'weight': 2
            })

        return checks



    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Обчислює відстань Левенштейна між двома рядками."""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]













