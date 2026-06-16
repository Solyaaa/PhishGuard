import hashlib
import re
import ssl
import socket
import whois
import math
import requests
import tldextract
import dns.resolver
from urllib.parse import urlparse
from datetime import datetime, timedelta
from bs4 import BeautifulSoup
import concurrent.futures
import logging
from typing import Dict, List, Any, Union, Tuple
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import os
import time
import base64  # Для VirusTotal API


from config.config import (
    PHISHING_THRESHOLD_SCORE,
    WARNING_THRESHOLD_SCORE,
    USER_AGENT, REQUEST_TIMEOUT,
    BLACKLISTS, VIRUSTOTAL_API_KEY
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FeatureExtractor:
    """Клас для перетворення URL у числовий вектор ознак для ML."""

    def extract_features(self, url: str) -> Dict[str, float]:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""

        def get_entropy(text):
            if not text: return 0
            probs = [text.count(c) / len(text) for c in set(text)]
            return -sum(p * math.log2(p) for p in probs)

        features = {
            "url_length": len(url),
            "hostname_length": len(hostname),
            "dot_count": url.count('.'),
            "digit_ratio": sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0,
            "is_https": 1 if parsed.scheme == 'https' else 0,
            "subdomain_count": max(0, hostname.count('.') - 1),
            "entropy": round(get_entropy(url), 3),
            "special_char_count": sum(url.count(c) for c in ['@', '?', '&', '=', '_'])
        }
        return features
class PhishDetector:
    """
    Клас для виявлення фішингових URL за допомогою різних методів,
    включаючи інтеграцію з зовнішніми API (лише VirusTotal).
    """

    def __init__(self):
        """Ініціалізує PhishDetector з необхідними конфігураціями."""
        self.phishing_risk_threshold = PHISHING_THRESHOLD_SCORE
        self.warning_risk_threshold = WARNING_THRESHOLD_SCORE
        self.user_agent = USER_AGENT
        self.timeout = REQUEST_TIMEOUT

        self.virustotal_api_key = VIRUSTOTAL_API_KEY
        self.feature_extractor = FeatureExtractor()  # Ініціалізація ML-модуля
        self.virustotal_api_url_submission = "https://www.virustotal.com/api/v3/urls"
        self.virustotal_api_url_analysis = "https://www.virustotal.com/api/v3/analyses"
        self.virustotal_api_url_info = "https://www.virustotal.com/api/v3/urls"

        self.blacklists = BLACKLISTS

        cache_file = "blacklist_dynamic.txt"
        self.blacklist_full_urls, self.blacklist_domains = self._load_blacklists_with_cache(cache_file)

        self.MAX_POSSIBLE_RISK_SCORE = 1200

        self.login_form_patterns = [
            r'<form[^>]*action=["\']?[^"\']*login[^"\']*["\']?[^>]*>',
            r'<input[^>]*type=["\']?password["\']?[^>]*>',
            r'<form[^>]*action=["\']?[^"\']*sign-in[^"\']*["\']?[^>]*>'
        ]
        self.suspicious_form_keywords = [
            'login', 'signin', 'password', 'username', 'account', 'verify',
            'update', 'security', 'billing', 'confirm', 'paypal', 'bank',
            'credit card', 'ssn', 'social security'
        ]

    def _load_blacklists_with_cache(self, cache_file: str) -> Tuple[set, set]:
        full_urls = set()
        domains = set()
        last_modified = 0

        if os.path.exists(cache_file):
            last_modified = os.path.getmtime(cache_file)


        if (time.time() - last_modified) > 3600 or not os.path.exists(cache_file):
            logger.info("Оновлення чорного списку...")
            try:
                # Завантаження з зовнішніх джерел
                for url_list_path in self.blacklists:
                    response = requests.get(url_list_path, timeout=self.timeout)
                    response.raise_for_status()
                    for line in response.text.splitlines():
                        line = line.strip()
                        if line and not line.startswith('#'):
                            full_urls.add(line)
                            extracted = tldextract.extract(line)
                            if extracted.domain and extracted.suffix:
                                domains.add(f"{extracted.domain}.{extracted.suffix}")


                if os.path.exists('blacklist_dynamic.txt'):
                    with open('blacklist_dynamic.txt', 'r', encoding='utf-8') as f:
                        for line in f:
                            line = line.strip()
                            if line:
                                full_urls.add(line)
                                extracted = tldextract.extract(line)
                                if extracted.domain and extracted.suffix:
                                    domains.add(f"{extracted.domain}.{extracted.suffix}")


                with open(cache_file, 'w', encoding='utf-8') as f:
                    for url_item in full_urls:
                        f.write(url_item + '\n')
                logger.info(f"Чорний список оновлено. Завантажено {len(full_urls)} URL та {len(domains)} доменів.")
            except requests.exceptions.RequestException as e:
                logger.error(f"Помилка завантаження чорного списку з {url_list_path}: {e}")
            except Exception as e:
                logger.error(f"Невідома помилка при обробці чорного списку: {e}")
        else:
            try:

                with open(cache_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            full_urls.add(line)
                            extracted = tldextract.extract(line)
                            if extracted.domain and extracted.suffix:
                                domains.add(f"{extracted.domain}.{extracted.suffix}")
                logger.info(f"Чорний список завантажено з кешу. {len(full_urls)} URL та {len(domains)} доменів.")
            except Exception as e:
                logger.error(f"Помилка завантаження кешованого чорного списку: {e}. Буде спроба оновити.")
                if os.path.exists(cache_file):
                    os.remove(cache_file)

                return self._load_blacklists_with_cache(cache_file)

        return full_urls, domains

    def check_password_leak(self, password: str) -> Dict[str, Any]:
        """
        Перевіряє пароль на витоки через Pwned Passwords API (k-Anonymity).
        """
        try:

            sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix = sha1_password[:5]
            suffix = sha1_password[5:]


            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url, timeout=self.timeout)
            response.raise_for_status()


            hashes = (line.split(':') for line in response.text.splitlines())
            for h, count in hashes:
                if h == suffix:
                    return {
                        "is_pwned": True,
                        "count": int(count),
                        "status": "danger",
                        "message": f"Цей пароль було знайдено у витоках {count} разів!"
                    }

            return {
                "is_pwned": False,
                "count": 0,
                "status": "safe",
                "message": "Пароль не знайдено у відомих витоках даних."
            }

        except Exception as e:
            logger.error(f"Помилка при перевірці пароля: {e}")
            return {"error": "Не вдалося перевірити пароль", "status": "error"}

    def _check_blacklist(self, url: str, domain: str) -> List[Dict[str, Any]]:
        checks = []
        is_blacklisted = False
        details = "URL та домен не знайдено у чорних списках."
        score = 0
        weight = 1


        self.blacklist_full_urls, self.blacklist_domains = self._load_blacklists_with_cache('blacklist_dynamic.txt')

        if url in self.blacklist_full_urls:
            is_blacklisted = True
            details = "URL знайдено у чорному списку."
            score = 100
        elif domain in self.blacklist_domains:
            is_blacklisted = True
            details = "Домен знайдено у чорному списку."
            score = 80

        if is_blacklisted:
            checks.append({
                'description': 'Чорний список',
                'details': details,
                'result': 'fail',
                'score': score,
                'weight': weight
            })
        else:
            checks.append({
                'description': 'Чорний список',
                'details': details,
                'result': 'pass',
                'score': score,
                'weight': weight
            })
        return checks

    def scan_url(self, url: str, client_ip: str) -> Dict[str, Any]:
        """Об'єднаний метод: повний аналіз + інтелектуальні ознаки ML."""
        checks = []
        total_risk_score = 0
        final_safety_score = 100
        is_phishing = False
        domain = ""
        ip_address = "Не визначено"

        # --- КРОК 1: Вилучення ознак для ML та збереження в екземпляр класу ---
        # Це те, що ми додали для наукової новизни [cite: 43]
        self.current_ml_features = self.feature_extractor.extract_features(url)

        try:
            parsed_url = urlparse(url)
            if not parsed_url.scheme:
                url = "https://" + url
                parsed_url = urlparse(url)

            if not parsed_url.hostname:
                checks.append({
                    'description': 'Парсинг URL',
                    'details': 'Недійсний URL: не вдалося витягти ім\'я хоста.',
                    'result': 'fail', 'score': 100, 'weight': 10
                })
                return self._build_result(url, "Не визначено", checks, 0, True, client_ip)

            extracted = tldextract.extract(url)
            domain = f"{extracted.domain}.{extracted.suffix}" if extracted.domain and extracted.suffix else parsed_url.hostname

            # Визначення IP-адреси [cite: 184]
            try:
                if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", parsed_url.hostname):
                    ip_address = socket.gethostbyname(parsed_url.hostname)
                else:
                    ip_address = parsed_url.hostname
            except socket.gaierror:
                ip_address = "Не визначено"

            # --- КРОК 2: Додавання ML-перевірки (Ентропія) у список checks ---
            if self.current_ml_features['entropy'] > 4.2:
                total_risk_score += 100
                checks.append({
                    'description': 'ML: Аналіз ентропії',
                    'details': f"Висока ентропія URL ({self.current_ml_features['entropy']}). Ознака генерації алгоритмом.",
                    'result': 'warning', 'score': 100, 'weight': 1
                })

            # --- КРОК 3: Стандартні перевірки (Сигнатури та Евристика) ---
            # Перевірка чорних списків [cite: 136, 231]
            blacklist_checks = self._check_blacklist(url, domain)
            checks.extend(blacklist_checks)
            for check in blacklist_checks:
                if check['result'] == 'fail':
                    return self._build_result(url, domain, checks, 0, True, client_ip)

            # Перевірка VirusTotal [cite: 136, 182, 235]
            virustotal_checks = self._check_virustotal(url)
            checks.extend(virustotal_checks)
            for check in virustotal_checks:
                if check['result'] == 'phishing':
                    return self._build_result(url, domain, checks, 0, True, client_ip)
                total_risk_score += check['score'] * check.get('weight', 1)

            # Перевірка Google Safe Browsing [cite: 136, 183, 232]
            google_checks = self._check_google_safe_browsing(url)
            checks.extend(google_checks)
            for check in google_checks:
                if check['result'] == 'phishing':
                    return self._build_result(url, domain, checks, 0, True, client_ip)

            # Додаткові аналізи [cite: 136]
            self._check_ssl_certificate(url, checks)  # [cite: 229]
            self._check_domain_age(domain, checks)  # [cite: 243]
            self._check_brand_similarity(url, checks)  # [cite: 113, 239]
            self._check_page_content(url, checks)  # [cite: 209, 246]

            # Підрахунок фінального балу для всіх не-сигнатурних перевірок
            for check in checks:
                if check['description'] not in ['Чорний список', 'VirusTotal', 'Google Safe Browsing',
                                                'ML: Аналіз ентропії']:
                    if check['result'] in ['fail', 'warning', 'phishing']:
                        total_risk_score += check['score'] * check.get('weight', 1)

            # --- КРОК 4: Фіналізація результатів ---
            is_phishing = total_risk_score >= self.phishing_risk_threshold
            effective_risk = min(total_risk_score, self.MAX_POSSIBLE_RISK_SCORE)
            final_safety_score = max(0, 100 - int((effective_risk / self.MAX_POSSIBLE_RISK_SCORE) * 100))

            if is_phishing:
                final_safety_score = min(final_safety_score, 10)
            elif total_risk_score >= self.warning_risk_threshold:
                final_safety_score = min(final_safety_score, 60)

        except Exception as e:
            logger.exception(f"Помилка аналізу {url}: {e}")
            is_phishing = True
            final_safety_score = 0

        return self._build_result(url, domain, checks, final_safety_score, is_phishing, ip_address)

    def _check_google_safe_browsing(self, url: str) -> List[Dict[str, Any]]:
        """Перевірка URL через Google Safe Browsing API."""
        api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
        if not api_key:
            return [{
                'description': 'Google Safe Browsing',
                'details': 'API ключ Google не налаштовано.',
                'result': 'info',
                'score': 0, 'weight': 0
            }]

        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        payload = {
            "client": {"clientId": "phishguard", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        try:
            response = requests.post(endpoint, json=payload, timeout=self.timeout)
            data = response.json()
            if "matches" in data:
                return [{
                    'description': 'Google Safe Browsing',
                    'details': f'🚨 Google знайшов загрозу: {data["matches"][0]["threatType"]}',
                    'result': 'phishing',
                    'score': 800, 'weight': 5
                }]
        except Exception as e:
            logger.error(f"Помилка Google API: {e}")

        return [{
            'description': 'Google Safe Browsing',
            'details': 'Google не виявив загроз для цього URL.',
            'result': 'pass',
            'score': 0, 'weight': 1
        }]



    def _check_virustotal(self, url: str) -> List[Dict[str, Any]]:
        checks = []
        if not self.virustotal_api_key:
            checks.append({
                'description': 'VirusTotal',
                'details': 'API ключ VirusTotal не налаштовано.',
                'result': 'warning',
                'score': 0,
                'weight': 0
            })
            return checks

        headers = {
            "x-apikey": self.virustotal_api_key,
            "Content-Type": "application/x-www-form-urlencoded"
        }

        payload = f"url={url}"

        try:

            submission_response = requests.post(
                self.virustotal_api_url_submission,
                headers=headers,
                data=payload,
                timeout=self.timeout
            )
            submission_response.raise_for_status()
            submission_json = submission_response.json()
            analysis_id = submission_json.get("data", {}).get("id")

            if not analysis_id:
                raise ValueError("Не вдалося отримати ID аналізу з відповіді VirusTotal.")


            max_retries = 5
            retry_delay = 5
            for i in range(max_retries):
                time.sleep(retry_delay)

                analysis_url = f"{self.virustotal_api_url_analysis}/{analysis_id}"
                analysis_response = requests.get(
                    analysis_url,
                    headers=headers,
                    timeout=self.timeout
                )
                analysis_response.raise_for_status()
                analysis_json = analysis_response.json()
                analysis_status = analysis_json.get("data", {}).get("attributes", {}).get("status")

                if analysis_status == "completed":

                    results = analysis_json.get("data", {}).get("attributes", {}).get("results", {})
                    malicious_votes = 0
                    harmless_votes = 0
                    undetected_votes = 0

                    for engine, data in results.items():
                        if data.get("category") == "malicious":
                            malicious_votes += 1
                        elif data.get("category") == "harmless":
                            harmless_votes += 1
                        elif data.get("category") == "undetected":
                            undetected_votes += 1

                    if malicious_votes > 0:
                        checks.append({
                            'description': 'VirusTotal',
                            'details': f'VirusTotal виявив фішинг: {malicious_votes} шкідливих виявлень.',
                            'result': 'phishing',
                            'score': 500 + (malicious_votes * 50),
                            'weight': 5
                        })
                    else:
                        checks.append({
                            'description': 'VirusTotal',
                            'details': f'VirusTotal не виявив фішингу. Виявлено: {malicious_votes} шкідливих, {harmless_votes} нешкідливих.',
                            'result': 'pass',
                            'score': 0,
                            'weight': 5
                        })
                    return checks


            checks.append({
                'description': 'VirusTotal',
                'details': 'URL успішно відправлено на аналіз, але результати не були доступні протягом очікуваного часу.',
                'result': 'info',
                'score': 0,
                'weight': 3
            })

        except requests.exceptions.HTTPError as e:
            error_msg = f"Помилка HTTP {e.response.status_code}: {e.response.text}"
            checks.append({
                'description': 'VirusTotal',
                'details': error_msg,
                'result': 'warning',
                'score': 50,
                'weight': 5
            })
        except Exception as e:
            checks.append({
                'description': 'VirusTotal',
                'details': f"Помилка VirusTotal: {str(e)}",
                'result': 'warning',
                'score': 50,
                'weight': 5
            })

        return checks

    def _check_ssl_certificate(self, url: str, checks: List[Dict[str, Any]]):
        """Перевіряє SSL-сертифікат URL."""
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        if not hostname:
            checks.append({
                'description': 'SSL-сертифікат',
                'details': 'Не вдалося витягти ім\'я хоста для перевірки SSL.',
                'result': 'info',
                'score': 0,
                'weight': 0
            })
            return

        try:

            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y GMT')
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y GMT')

                    subject_alt_names = [item[1] for item in cert['subjectAltName'] if item[0] == 'DNS']

                    current_time = datetime.utcnow()

                    if not_before > current_time or not_after < current_time:
                        checks.append({
                            'description': 'SSL-сертифікат',
                            'details': 'Сертифікат недійсний (термін дії закінчився або ще не почався).',
                            'result': 'warning',
                            'score': 50,
                            'weight': 1
                        })

                    elif not any(hostname == san or (san.startswith('*.') and hostname.endswith(san[1:])) for san in
                                 subject_alt_names):
                        checks.append({
                            'description': 'SSL-сертифікат',
                            'details': 'Ім\'я хоста не відповідає сертифікату.',
                            'result': 'warning',
                            'score': 40,
                            'weight': 1
                        })
                    else:
                        checks.append({
                            'description': 'SSL-сертифікат',
                            'details': f'Сертифікат дійсний і відповідає домену. Виданий до: {not_after.strftime("%Y-%m-%d")}',
                            'result': 'pass',
                            'score': 0,
                            'weight': 1
                        })
        except ssl.CertificateError as e:
            checks.append({
                'description': 'SSL-сертифікат',
                'details': f'Помилка сертифіката SSL: {e}',
                'result': 'warning',
                'score': 60,
                'weight': 1
            })
        except (socket.timeout, ConnectionRefusedError, socket.gaierror, ssl.SSLError) as e:

            checks.append({
                'description': 'SSL-сертифікат',
                'details': f'Неможливо встановити SSL-з\'єднання або отримати сертифікат: {e}. (Можливо, сайт не використовує HTTPS або є проблеми з мережею)',
                'result': 'info',
                'score': 0,
                'weight': 1
            })
        except Exception as e:
            logger.error(f"Невідома помилка SSL-перевірки для {url}: {e}", exc_info=True)
            checks.append({
                'description': 'SSL-сертифікат',
                'details': f'Невідома помилка під час перевірки SSL: {e}',
                'result': 'fail',
                'score': 20,
                'weight': 1
            })

    def _check_domain_age(self, domain: str, checks: List[Dict[str, Any]]):
        """Перевіряє вік домену за допомогою whois."""
        try:
            w = whois.whois(domain)
            if w and w.creation_date:

                creation_date = w.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]


                if isinstance(creation_date, datetime):
                    age_days = (datetime.now() - creation_date).days
                    if age_days < 90:
                        checks.append({
                            'description': 'Вік домену',
                            'details': f'Домену {age_days} днів. Дуже молодий домен.',
                            'result': 'phishing',
                            'score': 150,
                            'weight': 2
                        })
                    elif age_days < 365:
                        checks.append({
                            'description': 'Вік домену',
                            'details': f'Домену {age_days} днів. Молодий домен.',
                            'result': 'warning',
                            'score': 80,
                            'weight': 1
                        })
                    else:
                        checks.append({
                            'description': 'Вік домену',
                            'details': f'Домену {age_days} днів. Достатньо старий.',
                            'result': 'pass',
                            'score': 0,
                            'weight': 1
                        })
                else:
                    checks.append({
                        'description': 'Вік домену',
                        'details': 'Не вдалося визначити дату створення домену (недійсний формат дати WHOIS).',
                        'result': 'info',
                        'score': 0,
                        'weight': 0
                    })
            else:
                checks.append({
                    'description': 'Вік домену',
                    'details': 'Не вдалося визначити дату створення домену (відсутні дані WHOIS).',
                    'result': 'info',
                    'score': 0,
                    'weight': 0
                })
        except Exception as e:
            logger.error(f"Помилка WHOIS запиту для домену {domain}: {e}", exc_info=True)
            checks.append({
                'description': 'Вік домену',
                'details': f'Помилка WHOIS запиту: {str(e)}',
                'result': 'info',
                'score': 0,
                'weight': 0
            })

    def _check_brand_similarity(self, url: str, checks: List[Dict[str, Any]]):
        """
        Перевіряє схожість домену з відомими брендами або наявність омогліфів.
        """
        parsed_url = urlparse(url)
        domain = parsed_url.hostname
        if not domain:
            checks.append({
                'description': 'Схожість з брендом/Омогліфи',
                'details': 'Не вдалося витягти домен для перевірки схожості.',
                'result': 'info',
                'score': 0,
                'weight': 0
            })
            return


        known_brands = ['google', 'facebook', 'microsoft', 'apple', 'amazon', 'paypal', 'bankofamerica',
                        'chase', 'telegram', 'instagram', 'twitter', 'netflix', 'steam', 'blizzard',
                        'discord', 'ebay', 'wikipedia', 'linkedin', 'protonmail', 'coinbase', 'binance',
                        'trustwallet', 'metamask']
        extracted = tldextract.extract(url)
        target_domain = extracted.domain.lower()

        is_similar = False
        for brand in known_brands:
            distance = self._levenshtein_distance(target_domain, brand)

            if distance <= (len(brand) // 4) or (
                    distance <= 2 and len(brand) > 5):
                checks.append({
                    'description': 'Схожість з брендом/Омогліфи',
                    'details': f'Домен "{target_domain}" схожий на відомий бренд "{brand}" (відстань Левенштейна: {distance}).',
                    'result': 'phishing',
                    'score': 200,
                    'weight': 3
                })
                is_similar = True
                break
        if not is_similar:
            checks.append({
                'description': 'Схожість з брендом/Омогліфи',
                'details': 'Домен не виявлено як схожий на відомі бренди.',
                'result': 'pass',
                'score': 0,
                'weight': 1
            })

    def _check_page_content(self, url: str, checks: List[Dict[str, Any]]):
        """
        Аналізує контент сторінки на наявність форм входу або підозрілих ключових слів.
        """
        try:
            response = requests.get(url, headers={'User-Agent': self.user_agent}, timeout=self.timeout, verify=False)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')

            form_found = False
            for pattern in self.login_form_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    form_found = True
                    checks.append({
                        'description': 'Контент сторінки: Форми входу',
                        'details': 'Виявлено форму, схожу на форму входу.',
                        'result': 'warning',
                        'score': 100,
                        'weight': 2
                    })
                    break
            if not form_found:
                checks.append({
                    'description': 'Контент сторінки: Форми входу',
                    'details': 'Форм входу не виявлено.',
                    'result': 'pass',
                    'score': 0,
                    'weight': 1
                })

            found_keywords = []
            page_text = soup.get_text().lower()
            for keyword in self.suspicious_form_keywords:
                if keyword in page_text:
                    if keyword not in [f.lower() for f in found_keywords]:
                        found_keywords.append(keyword)

            if found_keywords:
                checks.append({
                    'description': 'Контент сторінки: Ключові слова',
                    'details': f'Сторінка містить підозрілі ключові слова: {", ".join(found_keywords)}',
                    'result': 'warning',
                    'score': 60 * len(found_keywords),
                    'weight': 2
                })
            else:
                checks.append({
                    'description': 'Контент сторінки: Ключові слова',
                    'details': 'Підозрілих ключових слів не виявлено.',
                    'result': 'pass',
                    'score': 0,
                    'weight': 1
                })

        except requests.exceptions.RequestException as e:
            logger.error(f"Помилка завантаження контенту сторінки {url}: {e}")
            checks.append({
                'description': 'Контент сторінки',
                'details': f'Помилка завантаження контенту сторінки: {str(e)}',
                'result': 'fail',
                'score': 70,
                'weight': 2
            })
        except Exception as e:
            logger.error(f"Внутрішня помилка при аналізі контенту сторінки {url}: {e}", exc_info=True)
            checks.append({
                'description': 'Контент сторінки',
                'details': f'Внутрішня помилка при аналізі контенту сторінки: {str(e)}',
                'result': 'fail',
                'score': 70,
                'weight': 2
            })

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

    # def scan_url(self, url: str, client_ip: str) -> Dict[str, Any]:
    #     checks = []
    #     total_risk_score = 0
    #     final_safety_score = 100
    #     is_phishing = False
    #     domain = ""
    #     ip_address = "Не визначено"
    #
    #     try:
    #         parsed_url = urlparse(url)
    #
    #         if not parsed_url.scheme:
    #
    #             url = "https://" + url
    #             parsed_url = urlparse(url)
    #
    #         if not parsed_url.hostname:
    #             checks.append({
    #                 'description': 'Парсинг URL',
    #                 'details': 'Недійсний URL: не вдалося витягти ім\'я хоста.',
    #                 'result': 'fail',
    #                 'score': 100,
    #                 'weight': 10
    #             })
    #
    #             return self._build_result(url, "Не визначено", checks, 0, True, client_ip)
    #
    #
    #         extracted = tldextract.extract(url)
    #         domain = f"{extracted.domain}.{extracted.suffix}" if extracted.domain and extracted.suffix else parsed_url.hostname
    #
    #         try:
    #             # Перевірка, чи не є hostname вже IP адресою
    #             if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", parsed_url.hostname):
    #                 ip_address = socket.gethostbyname(parsed_url.hostname)
    #             else:
    #                 ip_address = parsed_url.hostname
    #         except socket.gaierror:
    #             ip_address = "Не визначено"
    #             logger.warning(f"Не вдалося визначити IP-адресу для хоста: {parsed_url.hostname}")
    #
    #         # -----------------------------------------------------------
    #         # ШВИДКА ВІДМОВА (FAIL-FAST) - ЧОРНІ СПИСКИ та VirusTotal
    #         # -----------------------------------------------------------
    #
    #
    #         blacklist_checks = self._check_blacklist(url, domain)
    #         checks.extend(blacklist_checks)
    #         for check in blacklist_checks:
    #             if check['result'] == 'fail':
    #                 total_risk_score += check['score'] * check['weight']
    #                 is_phishing = True
    #                 logger.info(f"URL {url} ідентифіковано як фішинг за чорним списком (ШВИДКА ВІДМОВА).")
    #                 return self._build_result(url, domain, checks, 0, is_phishing, client_ip)
    #
    #
    #         virustotal_checks = self._check_virustotal(url)
    #         checks.extend(virustotal_checks)
    #         for check in virustotal_checks:
    #
    #             if check['result'] == 'phishing':
    #                 total_risk_score += check['score'] * check['weight']
    #                 is_phishing = True
    #                 logger.info(f"URL {url} ідентифіковано як фішинг за VirusTotal (ШВИДКА ВІДМОВА).")
    #                 return self._build_result(url, domain, checks, 0, is_phishing, client_ip)
    #
    #             elif check['score'] > 0:
    #                 total_risk_score += check['score'] * check['weight']
    #
    #         google_checks = self._check_google_safe_browsing(url)
    #         checks.extend(google_checks)
    #         for check in google_checks:
    #             if check['result'] == 'phishing':
    #                 total_risk_score += check['score'] * check['weight']
    #                 is_phishing = True
    #                 logger.info(f"URL {url} ідентифіковано як фішинг за Google Safe Browsing.")
    #                 return self._build_result(url, domain, checks, 0, is_phishing, client_ip)
    #         # -----------------------------------------------------------
    #         # ПРОДОВЖЕННЯ ПОВНОЇ ПЕРЕВІРКИ, ЯКЩО НЕМАЄ ШВИДКОЇ ВІДМОВИ
    #         # -----------------------------------------------------------
    #         logger.info(f"URL {url} не спричинив швидку відмову. Продовжую повний аналіз.")
    #
    #
    #         self._check_ssl_certificate(url, checks)
    #         self._check_domain_age(domain, checks)
    #         self._check_brand_similarity(url, checks)
    #         self._check_page_content(url, checks)
    #
    #
    #         for check in checks:
    #
    #             if check['description'] not in ['Чорний список', 'VirusTotal','Google Safe Browsing']:
    #                 if check['result'] in ['fail', 'warning', 'phishing']:
    #                     total_risk_score += check['score'] * check.get('weight', 1)
    #
    #         logger.info(f"Загальний бал ризику для {url} після повного аналізу: {total_risk_score}")
    #
    #
    #         if total_risk_score >= self.phishing_risk_threshold:
    #             is_phishing = True
    #         elif total_risk_score >= self.warning_risk_threshold:
    #             is_phishing = False
    #         else:
    #             is_phishing = False
    #
    #
    #         if self.MAX_POSSIBLE_RISK_SCORE > 0:
    #
    #             effective_risk_score = min(total_risk_score, self.MAX_POSSIBLE_RISK_SCORE)
    #             final_safety_score = max(0, 100 - int((effective_risk_score / self.MAX_POSSIBLE_RISK_SCORE) * 100))
    #         else:
    #             final_safety_score = 100
    #
    #
    #         if is_phishing:
    #             final_safety_score = min(final_safety_score, 10)
    #         elif total_risk_score >= self.warning_risk_threshold:
    #             final_safety_score = min(final_safety_score,
    #                                      60)
    #
    #     except Exception as e:
    #         logger.exception(f"Загальна помилка при аналізі URL {url}: {e}")
    #         checks.append({
    #             'description': 'Загальна помилка',
    #             'details': f'Виникла непередбачена помилка: {str(e)}',
    #             'result': 'fail',
    #             'score': 100,
    #             'weight': 1
    #         })
    #         final_safety_score = 0
    #         is_phishing = True
    #
    #     return self._build_result(url, domain, checks, final_safety_score, is_phishing, ip_address)

    def _build_result(self, url: str, domain: str, checks: List[Dict[str, Any]],
                      final_score: int, is_phishing: bool, ip_address: str) -> Dict[str, Any]:
        """Формує стандартизований словник результатів з підтримкою ML-ознак."""

        # Визначаємо статус на основі результатів аналізу [cite: 156]
        status = "safe"
        if is_phishing:
            status = "phishing"
        elif final_score < self.warning_risk_threshold:
            status = "warning"

        # Створюємо базовий результат [cite: 196]
        result = {
            'url': url,
            'domain': domain,
            'ip_address': ip_address,
            'final_score': final_score,
            'is_phishing': is_phishing,
            'checks': checks,
            'status': status
        }

        # ПЕРЕВІРКА: додаємо ml_features, якщо вони були згенеровані під час сканування [cite: 197]
        # Це дозволяє передати вектори ознак у app.py для запису в MongoDB [cite: 205, 291]
        if hasattr(self, 'current_ml_features'):
            result['ml_features'] = self.current_ml_features

        return result