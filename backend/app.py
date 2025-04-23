from flask import Flask, request, jsonify, render_template, abort
from datetime import datetime
import os
import logging
from dotenv import load_dotenv
from pymongo import MongoClient
from bson import ObjectId
import json
import certifi


from phish_detector import PhishDetector
from db_models import ScanResult, UserFeedback, ReportedDomain
from utils import JSONEncoder


load_dotenv()


app = Flask(__name__,
            static_folder='../frontend/static',
            template_folder='../frontend/templates')


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:

    mongo_uri = "mongodb+srv://newUser:89868414@cluster9.m5sn2.mongodb.net/phishguard?retryWrites=true&w=majority&appName=Cluster9"
    client = MongoClient(mongo_uri,
                         tlsCAFile=certifi.where(),
                         serverSelectionTimeoutMS=5000)


    db = client["phishguard"]

    client.admin.command('ping')
    logger.info("Успішне підключення до MongoDB")
except Exception as e:
    logger.error(f"Не вдалося підключитися до MongoDB: {e}")
    db = None

# Ініціалізація детектора фішингу
detector = PhishDetector()

# Налаштування JSON енкодера для правильної обробки ObjectId та datetime
app.json_encoder = JSONEncoder


@app.route('/')
def index():
    """Відображення головної сторінки."""
    return render_template('index.html')


@app.route('/api/analyze', methods=['POST'])
def analyze_url():
    """Аналіз URL на наявність ознак фішингу."""
    try:
        data = request.get_json()

        if not data or 'url' not in data:
            return jsonify({"error": "URL не вказано"}), 400

        url = data['url']
        logger.info(f"Аналізуємо URL: {url}")

        # Запуск аналізу
        analysis_result = detector.analyze_url(url)

        # Збереження результату в MongoDB, якщо підключення доступне
        try:
            if db is not None:
                scan_result = ScanResult(
                    url=analysis_result['url'],
                    domain=analysis_result['domain'],
                    checks=analysis_result['checks'],
                    final_score=analysis_result['final_score'],
                    is_phishing=analysis_result['is_phishing'],
                    ip_address=request.remote_addr
                )
                db.scan_results.insert_one(scan_result.to_dict())
                logger.info(f"Результат аналізу збережено для {url}")
        except Exception as db_error:
            logger.error(f"Помилка збереження в MongoDB: {str(db_error)}")
            # Продовжуємо виконання, навіть якщо збереження не вдалося

        # Повернення результату
        return jsonify(analysis_result)

    except Exception as e:
        logger.error(f"Помилка аналізу URL: {str(e)}")
        return jsonify({"error": f"Виникла помилка: {str(e)}"}), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Отримання статистичної інформації про перевірки."""
    try:
        if db is  None:
            return jsonify({"error": "Підключення до бази даних недоступне"}), 503

        total_scans = db.scan_results.count_documents({})
        phishing_detected = db.scan_results.count_documents({"is_phishing": True})

        # Останні 10 перевірок
        recent_scans = list(db.scan_results.find().sort("created_at", -1).limit(10))

        # Топ-5 доменів з фішингом
        top_phishing_domains = list(db.scan_results.aggregate([
            {"$match": {"is_phishing": True}},
            {"$group": {"_id": "$domain", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 5}
        ]))

        stats = {
            "total_scans": total_scans,
            "phishing_detected": phishing_detected,
            "detection_rate": round((phishing_detected / total_scans) * 100, 2) if total_scans > 0 else 0,
            "recent_scans": recent_scans,
            "top_phishing_domains": top_phishing_domains
        }

        return jsonify(stats)

    except Exception as e:
        logger.error(f"Помилка отримання статистики: {str(e)}")
        return jsonify({"error": f"Виникла помилка: {str(e)}"}), 500


@app.route('/api/report', methods=['POST'])
def report_problem():
    """Дозволяє користувачам повідомляти про помилкові результати."""
    try:
        data = request.get_json()

        if not data or 'scan_id' not in data or 'feedback_type' not in data:
            return jsonify({"error": "Відсутні обов'язкові поля"}), 400

        if db is  None:
            return jsonify({"error": "Підключення до бази даних недоступне"}), 503

        scan_id = data['scan_id']
        feedback_type = data['feedback_type']
        comment = data.get('comment', '')

        feedback = UserFeedback(
            scan_id=scan_id,
            feedback_type=feedback_type,
            comment=comment,
            ip_address=request.remote_addr
        )

        db.user_feedback.insert_one(feedback.to_dict())
        logger.info(f"Отримано відгук для сканування {scan_id}")

        return jsonify({"message": "Дякуємо за ваш відгук"})

    except Exception as e:
        logger.error(f"Помилка при надсиланні відгуку: {str(e)}")
        return jsonify({"error": f"Виникла помилка: {str(e)}"}), 500


@app.route('/api/report-phishing', methods=['POST'])
def report_phishing():
    """Прийом повідомлень про фішингові сайти."""
    try:
        data = request.get_json()

        if not data or 'url' not in data:
            return jsonify({"error": "URL не вказано"}), 400

        if db is None:
            return jsonify({"error": "Підключення до бази даних недоступне"}), 503

        url = data['url']
        comment = data.get('comment', '')

        # Розбір URL для отримання домену
        from tldextract import extract
        extracted = extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"

        # Створення запису про повідомлений фішинговий домен
        reported_domain = ReportedDomain(
            domain=domain,
            url=url,
            reporter_ip=request.remote_addr,
            comment=comment
        )

        db.reported_domains.insert_one(reported_domain.to_dict())
        logger.info(f"Отримано повідомлення про фішинговий сайт: {url}")

        return jsonify({"message": "Дякуємо за повідомлення. Наша команда перевірить цей сайт."})

    except Exception as e:
        logger.error(f"Помилка при повідомленні про фішинг: {str(e)}")
        return jsonify({"error": f"Виникла помилка: {str(e)}"}), 500


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Ресурс не знайдено"}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Внутрішня помилка сервера"}), 500


if __name__ == '__main__':
    # Конфігурація сервера для розробки
    debug_mode = os.getenv("DEBUG", "False").lower() in ("true", "1", "t")
    port = int(os.getenv("PORT", 8000))
    app.run(debug=debug_mode, host='0.0.0.0', port=port)
