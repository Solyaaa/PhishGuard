document.addEventListener('DOMContentLoaded', function() {
    let urlForm = document.getElementById('url-form');
    let urlInput = document.getElementById('url-input');
    let resultsSection = document.getElementById('results-section');
    let resultCard = document.getElementById('result-card');
    let scannedUrl = document.getElementById('scanned-url');
    let safetyScore = document.getElementById('safety-score');
    let resultStatus = document.getElementById('result-status');
    let checkList = document.getElementById('check-list');
    let newScanBtn = document.getElementById('new-scan-btn');

    // Обробник відправки форми
    urlForm.addEventListener('submit', function(e) {
        e.preventDefault();

        const url = urlInput.value.trim();
        if (!url) return;

        // Показати стан завантаження
        resultsSection.classList.remove('hidden');
        resultCard.innerHTML = `
            <div class="loading-spinner">
                <i class="fas fa-circle-notch fa-spin"></i>
                <p>Аналізуємо URL... Це може зайняти кілька секунд.</p>
            </div>
        `;

        // Зробити API-запит до бекенду
        fetch('/api/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: url })
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Помилка мережі');
            }
            return response.json();
        })
        .then(data => {
            console.log("Отримано дані:", data);  // Додайте це
            displayResults(url, data);
        })
        .catch(error => {
            displayError(error.message);
        });
    });

    // Обробник кнопки "Нова перевірка"
    newScanBtn.addEventListener('click', function() {
        urlInput.value = '';
        resultsSection.classList.add('hidden');
        window.scrollTo({ top: 0, behavior: 'smooth' });
    });

    // Функція відображення результатів
    function displayResults(url, data) {
    // Відновлюємо структуру картки результатів, якщо вона була замінена
        if (!document.getElementById('scanned-url')) {
            resultCard.innerHTML = `
                <div class="result-header">
                    <h3 id="scanned-url">${url}</h3>
                    <div class="score-badge" id="safety-score">${data.final_score}</div>
                </div>
                <div class="result-status" id="result-status"></div>
                <div class="result-details">
                    <h4>Детальний аналіз</h4>
                    <ul class="check-list" id="check-list"></ul>
                </div>
                <div class="result-actions">
                    <button class="btn-report">Повідомити про помилку</button>
                    <button class="btn-share">Поділитися</button>
                    <button class="btn-new-scan" id="new-scan-btn">Нова перевірка</button>
                </div>
            `;

            // Перепривласнюємо посилання на елементи
            scannedUrl = document.getElementById('scanned-url');
            safetyScore = document.getElementById('safety-score');
            resultStatus = document.getElementById('result-status');
            checkList = document.getElementById('check-list');
            newScanBtn = document.getElementById('new-scan-btn');

            // Повторно додаємо обробник подій
            newScanBtn.addEventListener('click', function() {
                urlInput.value = '';
                resultsSection.classList.add('hidden');
                window.scrollTo({ top: 0, behavior: 'smooth' });
            });
        } else {
            // Оновлюємо існуючі елементи
            scannedUrl.textContent = url;
            safetyScore.textContent = data.final_score;
        }


        // Оновити показник безпеки
        const score = data.final_score;
        safetyScore.textContent = score;

        // Встановити колір на основі оцінки
        if (score >= 80) {
            safetyScore.style.backgroundColor = 'var(--success-color)';
        } else if (score >= 50) {
            safetyScore.style.backgroundColor = 'var(--warning-color)';
        } else {
            safetyScore.style.backgroundColor = 'var(--danger-color)';
        }

        // Оновити повідомлення про статус
        let statusClass = score >= 80 ? '' : score >= 50 ? 'warning' : 'danger';
        let statusTitle = score >= 80 ? 'Безпечний сайт' : score >= 50 ? 'Потенційно небезпечний' : 'Ймовірний фішинг';
        let statusMessage = '';

        if (score >= 80) {
            statusMessage = 'Цей веб-сайт виглядає безпечним за результатами нашого аналізу.';
        } else if (score >= 50) {
            statusMessage = 'Цей веб-сайт має деякі підозрілі характеристики. Будьте обережні з наданням особистої інформації.';
        } else {
            statusMessage = 'Цей веб-сайт має ознаки фішингу. Рекомендуємо не відвідувати його.';
        }

        resultStatus.className = 'result-status ' + statusClass;
        resultStatus.innerHTML = `
            <h4>${statusTitle}</h4>
            <p>${statusMessage}</p>
        `;

        // Заповнити список перевірок
        checkList.innerHTML = '';

        data.checks.forEach(check => {
            let icon = '';
            let className = '';

            if (check.result === 'pass') {
                icon = 'check-circle';
                className = 'pass';
            } else if (check.result === 'warning') {
                icon = 'exclamation-triangle';
                className = 'warning';
            } else {
                icon = 'times-circle';
                className = 'fail';
            }

            const li = document.createElement('li');
            li.className = className;
            li.innerHTML = `<i class="fas fa-${icon}"></i> ${check.description}: ${check.details}`;
            checkList.appendChild(li);
        });

        // 🔽 ДОДАНО: логіку кнопки "Повідомити про помилку"
        const reportBtn = document.querySelector('.btn-report');
        if (reportBtn) {
            reportBtn.disabled = false;
            reportBtn.textContent = 'Повідомити про помилку';
            reportBtn.onclick = () => {
                if (!confirm(`Ви впевнені, що хочете додати цей URL до чорного списку?\n${url}`)) {
                    return;
                }

                fetch('/api/report-phishing', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: url, comment: '' })
                })
                .then(res => res.json())
                .then(data => {
                    alert(data.message || 'Дякуємо! URL додано до чорного списку.');
                    reportBtn.disabled = true;
                    reportBtn.textContent = 'Додано до чорного списку';
                })
                .catch(err => {
                    alert('Помилка надсилання повідомлення');
                    console.error(err);
                });
            };
        }
// 🔼


        // Прокрутити до результатів
        resultsSection.scrollIntoView({ behavior: 'smooth' });
    }

    // Функція відображення помилки
    function displayError(message) {
    resultCard.innerHTML = `
        <div class="error-message">
            <i class="fas fa-exclamation-circle"></i>
            <h3>Сталася помилка</h3>
            <p>${message}</p>
            <button class="btn-new-scan" onclick="location.reload()">Спробувати знову</button>
        </div>
         `;
    }

    // Обробка валідації URL
    urlInput.addEventListener('input', function() {
        validateUrl();
    });

    window.onerror = function(message, source, lineno, colno, error) {
    console.error(`Помилка: ${message} на ${source}:${lineno}:${colno}`);
    alert(`Сталася помилка: ${message}`);
    return true;
    };

    function validateUrl() {
        const url = urlInput.value.trim();
        const submitBtn = urlForm.querySelector('button[type="submit"]');

        if (!url) {
            submitBtn.disabled = true;
            return;
        }

        // Базова валідація URL
        try {
            new URL(url);
            urlInput.classList.remove('invalid');
            submitBtn.disabled = false;
        } catch (e) {
            if (!url.startsWith('http')) {
                // Спробувати додати https:// префікс і перевірити знову
                try {
                    new URL(`https://${url}`);
                    urlInput.value = `https://${url}`;
                    urlInput.classList.remove('invalid');
                    submitBtn.disabled = false;
                } catch (e) {
                    urlInput.classList.add('invalid');
                    submitBtn.disabled = true;
                }
            } else {
                urlInput.classList.add('invalid');
                submitBtn.disabled = true;
            }
        }
    }

    // Ініціалізувати валідацію
    validateUrl();
});
