from flask import Flask, request, jsonify, render_template
from dotenv import load_dotenv
from pymongo import MongoClient
from bson import ObjectId
import certifi
import os
import logging
import threading
from flask import Flask, request, jsonify
from tldextract import extract
from flask_caching import Cache
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime
from config.config import (
    DEBUG, PORT, MONGO_URI, CACHE_TYPE, CACHE_TTL, CACHE_REDIS_URL,
    RATE_LIMIT_ENABLED, RATE_LIMIT_PER_MINUTE, RATE_LIMIT_STORAGE_URL,
    setup_logging
)
from phish_detector import PhishDetector
from db_models import ScanResult, ReportedDomain
from utils import JSONEncoder


load_dotenv()
logger = setup_logging()
security_logger = logging.getLogger('security')

app = Flask(__name__, static_folder='../frontend/static', template_folder='../frontend/templates')
app.json_encoder = JSONEncoder

BLACKLIST_DYNAMIC_FILE = 'blacklist_dynamic.txt'
lock = threading.Lock()

@app.route('/api/report-phishing', methods=['POST'])
def report_phishing():
    try:
        data = request.get_json(force=True)
        url = data.get('url')
        if not url:
            return jsonify({"error": "URL не вказано"}), 400

        extracted = extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"

        report = ReportedDomain(
            domain=domain,
            url=url,
            reporter_ip=request.remote_addr,
            comment=data.get('comment', '')
        )

        if db is not None:
            db.reported_domains.insert_one(report.to_dict())

        # Запис у файл чорного списку
        with lock:
            with open(BLACKLIST_DYNAMIC_FILE, 'a', encoding='utf-8') as f:
                f.write(url.strip() + '\n')

        return jsonify({"message": "Дякуємо! URL додано до чорного списку."})
    except Exception as e:
        logger.exception("Помилка фішингового репорту")
        return jsonify({"error": "Помилка при додаванні до чорного списку"}), 500

# Налаштування кешу (Redis або simple)
app.config['CACHE_TYPE'] = CACHE_TYPE
app.config['CACHE_DEFAULT_TIMEOUT'] = CACHE_TTL
if CACHE_TYPE == 'redis':
    app.config['CACHE_REDIS_URL'] = CACHE_REDIS_URL
cache = Cache(app)

# Налаштування rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[f"{RATE_LIMIT_PER_MINUTE}/minute"] if RATE_LIMIT_ENABLED else [],
    storage_uri=RATE_LIMIT_STORAGE_URL if RATE_LIMIT_STORAGE_URL else None
)
limiter.init_app(app)


try:
    client = MongoClient(MONGO_URI, tlsCAFile=certifi.where(), serverSelectionTimeoutMS=5000)
    client.admin.command('ping')
    db = client.get_default_database()
    logger.info("Успішне підключення до MongoDB")
except Exception as e:
    logger.error(f"Помилка підключення до MongoDB: {e}")
    db = None


detector = PhishDetector() # Перейменовано phish_detector на detector для узгодженості

@app.before_request
def log_request_info():
    logger.info(
        f"Запит від {request.remote_addr} → {request.method} {request.path} "
        f"User-Agent: {request.headers.get('User-Agent', 'N/A')}"
    )
    suspicious = ["'", '"', ';', '--', '<script', 'DROP', 'SELECT', 'UNION']
    for param in list(request.args.values()) + list(request.form.values()):
        if any(x.lower() in str(param).lower() for x in suspicious):
            security_logger.warning(
                f"⚠️ Можлива інʼєкція: {request.remote_addr} → {request.path} | Параметр: {param}"
            )

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST']) # Змінено маршрут з /api/analyze на /api/scan
@limiter.limit("10/minute")
def scan_url(): # Змінено назву функції з analyze_url на scan_url
    try:
        data = request.get_json(force=True)
        url = data.get('url')
        if not url:
            security_logger.warning("Спроба сканування без URL.")
            return jsonify({"error": "URL не надано"}), 400

        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        security_logger.info(f"Запит на сканування від IP: {client_ip} для URL: {url}")

        # ЗМІНА ТУТ: Викликаємо detector.scan_url()
        scan_results = detector.scan_url(url, client_ip)

        if db is not None:
            scan_result_obj = ScanResult(
                url=scan_results['url'],
                domain=scan_results['domain'],
                checks=scan_results['checks'],
                final_score=scan_results['final_score'],
                is_phishing=scan_results['is_phishing'],
                ip_address=scan_results['ip_address'], # Використовуємо IP з результатів сканування
                status=scan_results['status'] # Додаємо статус
            )
            inserted_id = db.scan_results.insert_one(scan_result_obj.to_dict()).inserted_id
            scan_results['scan_id'] = str(inserted_id) # Додаємо ID до результатів, що повертаються фронтенду
            logger.info(f"Результати сканування збережено з ID: {inserted_id}")


        return jsonify(scan_results) # Повертаємо scan_results

    except Exception as e:
        logger.exception(f"Помилка при скануванні URL: {url}")
        return jsonify({"error": "Внутрішня помилка сервера. Будь ласка, спробуйте пізніше.", "details": str(e)}), 500

@app.route('/api/stats', methods=['GET'])
@cache.cached(timeout=CACHE_TTL)
def get_stats():
    try:
        if db is None:
            return jsonify({"error": "База даних недоступна"}), 503

        total = db.scan_results.count_documents({})
        phishing = db.scan_results.count_documents({"is_phishing": True})
        recent = list(db.scan_results.find().sort("created_at", -1).limit(10))
        top = list(db.scan_results.aggregate([
            {"$match": {"is_phishing": True}},
            {"$group": {"_id": "$domain", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 5}
        ]))

        return jsonify({
            "total_scans": total,
            "phishing_detected": phishing,
            "detection_rate": round((phishing / total) * 100, 2) if total else 0,
            "recent_scans": recent,
            "top_phishing_domains": top
        })
    except Exception as e:
        logger.exception("Помилка статистики")
        return jsonify({"error": "Помилка отримання статистики"}), 500

@app.route('/api/report', methods=['POST'])
def report_problem():
    try:
        data = request.get_json(force=True)
        if not all(k in data for k in ('scan_id', 'feedback_type')):
            return jsonify({"error": "Неповні дані"}), 400

        # Тут можна додати логіку для збереження відгуку користувача,
        # наприклад, оновлення запису в `scan_results` або створення нового запису.
        # Для прикладу, оновимо статус та додамо тип відгуку.
        scan_id = data['scan_id']
        feedback_type = data['feedback_type']
        comment = data.get('comment', '')

        if db is not None:
            db.scan_results.update_one(
                {'_id': ObjectId(scan_id)},
                {'$set': {'feedback_type': feedback_type, 'feedback_comment': comment, 'updated_at': datetime.utcnow()}}
            )
            logger.info(f"Відгук отримано для scan_id: {scan_id}, тип: {feedback_type}")

        return jsonify({"message": "Дякуємо за відгук"})
    except Exception as e:
        logger.exception("Помилка відгуку")
        return jsonify({"error": "Помилка збереження відгуку"}), 500



@app.errorhandler(404)
def not_found(_):
    security_logger.warning(f"404: {request.remote_addr} намагався отримати {request.path}")
    return jsonify({"error": "Ресурс не знайдено"}), 404

@app.errorhandler(500)
def internal_error(_):
    return jsonify({"error": "Внутрішня помилка сервера"}), 500

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=PORT)