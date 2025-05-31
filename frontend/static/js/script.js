document.addEventListener('DOMContentLoaded', function() {
    let urlForm = document.getElementById('url-form');
    let urlInput = document.getElementById('url-input');
    let resultsSection = document.getElementById('results-section');
    let resultCard = document.getElementById('result-card');
    // Ці змінні будуть перевизначені всередині displayResults після динамічного рендерингу
    let scannedUrlElem = null;
    let safetyScoreElem = null;
    let resultStatusElem = null;
    let checkListElem = null;
    let newScanBtnElem = null; // Поточна кнопка "Нова перевірка"
    const toastContainer = document.getElementById('toast-container'); // Новий елемент для toast
    const scanHistorySection = document.getElementById('scan-history-section'); // Новий елемент для історії
    const HISTORY_KEY = 'phishguard_scan_history';
    const maxHistoryItems = 5; // Кількість елементів в історії

    // Функція для показу спливаючих сповіщень
    function showToast(message, type = 'info', duration = 3000) {
        const toast = document.createElement('div');
        toast.classList.add('toast', type);
        toast.textContent = message;
        toastContainer.appendChild(toast);

        // Trigger reflow to ensure animation
        void toast.offsetWidth; // Force reflow

        toast.classList.add('show');

        setTimeout(() => {
            toast.classList.remove('show');
            // Remove the toast after transition ends to clean up DOM
            toast.addEventListener('transitionend', () => toast.remove());
        }, duration);
    }

    // Обробник відправки форми
    urlForm.addEventListener('submit', function(e) {
        e.preventDefault();

        const url = urlInput.value.trim();
        if (!url) {
            showToast('Будь ласка, введіть URL для перевірки.', 'warning');
            return;
        }

        // Приховати історію та показати секцію результатів
        scanHistorySection.classList.add('hidden');
        resultsSection.classList.remove('hidden');

        // Показати стан завантаження
        resultCard.innerHTML = `
            <div class="loading-spinner">
                <i class="fas fa-circle-notch fa-spin"></i>
                <p>Аналізуємо URL... Це може зайняти кілька секунд.</p>
            </div>
        `;
        showToast('Починаємо сканування URL...', 'info');

        // Зробити API-запит до бекенду
        fetch('/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: url })
        })
        .then(response => {
            if (!response.ok) {
                // Спробувати прочитати помилку з відповіді
                return response.json().then(err => { throw new Error(err.error || 'Помилка мережі'); });
            }
            return response.json();
        })
        .then(data => {
            console.log("Отримано дані від бекенду:", data);
            displayResults(data.url, data); // Передаємо data.url як перший аргумент
            showToast('Сканування завершено!', 'success');
        })
        .catch(error => {
            console.error('Помилка:', error);
            displayErrorMessage('Помилка при з\'єднанні з сервісом. Спробуйте пізніше.');
            showToast(`Сталася помилка: ${error.message}`, 'error', 5000);
        });
    });

    // Обробник кнопки "Нова перевірка" (тепер буде прив'язуватися динамічно)
    // Цей блок коду видаляємо, оскільки кнопка newScanBtn тепер створюється динамічно
    // і обробник додається безпосередньо у displayResults та displayErrorMessage.
    /*
    newScanBtn.addEventListener('click', function() {
        urlInput.value = '';
        resultsSection.classList.add('hidden');
        window.scrollTo({ top: 0, behavior: 'smooth' });
    });
    */

    // Функція відображення результатів
    function displayResults(url, data) {
        // Завжди перестворюємо вміст resultCard, щоб забезпечити свіжі посилання на елементи
        resultCard.innerHTML = `
            <h3>Результати перевірки</h3>
            <p>Перевірений URL: <strong id="scanned-url">${url}</strong></p>
            <div class="safety-score" id="safety-score">${data.final_score}%</div>
            <div class="status" id="result-status"></div>

            <div class="check-list" id="check-list">
                <h4>Деталі перевірки:</h4>
                </div>
            <div class="result-actions">
                <button id="new-scan-btn" class="button button-primary"><i class="fas fa-redo"></i> Нове сканування</button>
                <button id="report-problem-btn" class="button button-secondary" data-url="${data.url}" data-scan-id="${data.scan_id || ''}"><i class="fas fa-bug"></i> Повідомити про проблему</button>
                <button id="share-result-btn" class="button button-secondary"><i class="fas fa-share-alt"></i> Поділитися результатом</button>
            </div>
        `;

        // Перепривласнюємо посилання на елементи після оновлення DOM
        scannedUrlElem = document.getElementById('scanned-url');
        safetyScoreElem = document.getElementById('safety-score');
        resultStatusElem = document.getElementById('result-status');
        checkListElem = document.getElementById('check-list');
        newScanBtnElem = document.getElementById('new-scan-btn'); // Отримуємо посилання на нову кнопку

        // Оновити показник безпеки та його колір
        const score = data.final_score;
        safetyScoreElem.textContent = `${score}%`; // Додаємо знак відсотка

        // Встановити колір на основі оцінки (логіка не змінена)
        if (score >= 80) {
            safetyScoreElem.classList.add('score-good');
            safetyScoreElem.classList.remove('score-medium', 'score-bad');
        } else if (score >= 50) {
            safetyScoreElem.classList.add('score-medium');
            safetyScoreElem.classList.remove('score-good', 'score-bad');
        } else {
            safetyScoreElem.classList.add('score-bad');
            safetyScoreElem.classList.remove('score-good', 'score-medium');
        }

        // Оновити повідомлення про статус (логіка не змінена)
        let statusClass = '';
        let statusTitle = '';
        let statusMessage = '';

        if (score >= 80) {
            statusClass = 'status-safe'; // Ваш існуючий клас
            statusTitle = 'Безпечний сайт';
            statusMessage = 'Цей веб-сайт виглядає безпечним за результатами нашого аналізу.';
        } else if (score >= 50) {
            statusClass = 'status-warning'; // Ваш існуючий клас
            statusTitle = 'Потенційно небезпечний';
            statusMessage = 'Цей веб-сайт має деякі підозрілі характеристики. Будьте обережні з наданням особистої інформації.';
        } else {
            statusClass = 'status-danger'; // Ваш існуючий клас
            statusTitle = 'Ймовірний фішинг';
            statusMessage = 'Цей веб-сайт має ознаки фішингу. Рекомендуємо не відвідувати його.';
        }

        resultStatusElem.className = 'status ' + statusClass; // Оновлено, щоб використовувати існуючий клас status
        resultStatusElem.innerHTML = `
            <h4>${statusTitle}</h4>
            <p>${statusMessage}</p>
        `;

        // Заповнити список перевірок
        checkListElem.innerHTML = ''; // Використовуємо checkListElem
        data.checks.forEach(check => {
            let icon = '';
            let className = '';

            if (check.result === 'pass') {
                icon = 'check-circle';
                className = 'pass';
            } else if (check.result === 'warning') {
                icon = 'exclamation-triangle';
                className = 'warning';
            } else { // fail
                icon = 'times-circle';
                className = 'fail';
            }

            const div = document.createElement('div'); // Змінено з li на div
            div.className = `check-item ${className}`; // Додано клас check-item
            div.innerHTML = `
                <i class="check-icon fas fa-${icon}"></i>
                <div>
                    <strong>${check.description}:</strong> ${check.details}
                    <div class="check-details">Score: ${check.score}, Weight: ${check.weight}</div>
                </div>
            `;
            checkListElem.appendChild(div); // Використовуємо checkListElem
        });

        // Прив'язка обробників подій для кнопок після їх створення
        // Обробник для кнопки "Нове сканування"
        if (newScanBtnElem) {
            newScanBtnElem.addEventListener('click', function() {
                resultsSection.classList.add('hidden');
                urlInput.value = '';
                urlInput.classList.remove('invalid'); // Очистити клас invalid
                urlForm.querySelector('button[type="submit"]').disabled = true; // Вимкнути кнопку
                scanHistorySection.classList.remove('hidden'); // Показати історію
                renderScanHistory(); // Оновити історію
            });
        }

        // Обробник для кнопки "Повідомити про проблему"
        const reportProblemBtn = document.getElementById('report-problem-btn');
        if (reportProblemBtn) {
            reportProblemBtn.addEventListener('click', async () => {
                const reportedUrl = reportProblemBtn.dataset.url;
                const scanId = reportProblemBtn.dataset.scanId;

                const feedbackType = prompt("Будь ласка, опишіть проблему (наприклад, 'Це фішинг, але ви не виявили', 'Не фішинг, але виявлено'):");
                if (feedbackType) {
                    try {
                        const response = await fetch('/api/report', { // URL для відгуку
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify({
                                scan_id: scanId,
                                url: reportedUrl,
                                feedback_type: feedbackType
                            })
                        });

                        const data = await response.json();
                        if (response.ok) {
                            showToast('Дякуємо за ваш відгук! Ми розглянемо його.', 'success');
                        } else {
                            showToast(`Помилка при відправці відгуку: ${data.error}`, 'error');
                        }
                    } catch (error) {
                        console.error('Помилка відправки відгуку:', error);
                        showToast('Помилка з\'єднання при відправці відгуку.', 'error');
                    }
                }
            });
        }

        // Обробник для кнопки "Поділитися результатом"
        const shareResultBtn = document.getElementById('share-result-btn');
        if (shareResultBtn) {
            shareResultBtn.addEventListener('click', async () => {
                const urlToShare = data.url;
                const currentStatusText = resultStatusElem.querySelector('h4').textContent; // Отримуємо поточний статус
                const currentScore = data.final_score;

                const shareText = `Я перевірив(ла) URL "${urlToShare}" за допомогою PhishGuard. Статус: ${currentStatusText}. Бал безпеки: ${currentScore}%. Перевірте і ви: ${window.location.origin}`;

                try {
                    if (navigator.share) {
                        await navigator.share({
                            title: 'Результат перевірки PhishGuard',
                            text: shareText,
                            url: window.location.origin
                        });
                        showToast('Результатом поділилися!', 'success');
                    } else {
                        await navigator.clipboard.writeText(shareText);
                        showToast('Текст результату скопійовано до буфера обміну!', 'success');
                    }
                } catch (err) {
                    console.error('Помилка при спробі поділитися:', err);
                    showToast('Не вдалося поділитися результатом.', 'error');
                }
            });
        }


        // Зберігаємо результат у історію
        saveScanToHistory({
            url: data.url,
            // Передаємо score для історії, щоб вона могла використовувати ту ж логіку
            final_score: data.final_score,
            timestamp: new Date().toISOString()
        });

        // Прокрутити до результатів
        resultsSection.scrollIntoView({ behavior: 'smooth' });
    }

    // Функція відображення повідомлення про помилку
    function displayErrorMessage(message) {
        resultCard.innerHTML = `
            <div class="error-message">
                <i class="fas fa-exclamation-circle"></i>
                <h3>Сталася помилка</h3>
                <p>${message}</p>
                <button id="new-scan-btn" class="button button-primary"><i class="fas fa-redo"></i> Нове сканування</button>
            </div>
        `;
        // Переприв'язуємо обробник для нової кнопки
        newScanBtnElem = document.getElementById('new-scan-btn');
        if (newScanBtnElem) {
            newScanBtnElem.addEventListener('click', function() {
                resultsSection.classList.add('hidden');
                urlInput.value = '';
                urlInput.classList.remove('invalid');
                urlForm.querySelector('button[type="submit"]').disabled = true;
                scanHistorySection.classList.remove('hidden');
                renderScanHistory();
            });
        }
    }

    // Обробка валідації URL
    urlInput.addEventListener('input', function() {
        validateUrl();
    });

    window.onerror = function(message, source, lineno, colno, error) {
        console.error(`Помилка: ${message} на ${source}:${lineno}:${colno}`);
        showToast(`Сталася непередбачена помилка: ${message}`, 'error', 5000);
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
                    urlInput.value = `https://${url}`; // Автоматично виправляє URL
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

    // Функції для історії сканувань
    function saveScanToHistory(scanResult) {
        let history = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
        history.unshift(scanResult); // Додати на початок
        history = history.slice(0, maxHistoryItems); // Обмежити кількість
        localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
        renderScanHistory(); // Оновити відображення історії
    }

    function renderScanHistory() {
        const historyList = scanHistorySection.querySelector('.history-list');
        if (!historyList) return;

        let history = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
        historyList.innerHTML = ''; // Очистити перед рендерингом

        if (history.length === 0) {
            historyList.innerHTML = '<p>Історія сканувань порожня.</p>';
            scanHistorySection.classList.remove('hidden'); // Показати секцію, навіть якщо порожня
            return;
        }

        scanHistorySection.classList.remove('hidden'); // Показати секцію, якщо є дані

        history.forEach(scan => {
            const item = document.createElement('div');
            item.classList.add('history-item');
            let statusClass = '';
            let statusText = '';
            // Використовуємо ТІ Ж пороги, що й для відображення результатів (не змінені)
            if (scan.final_score >= 80) {
                statusClass = 'status-safe'; // Ваш існуючий клас
                statusText = 'Безпечно';
            } else if (scan.final_score >= 50) {
                statusClass = 'status-warning'; // Ваш існуючий клас
                statusText = 'Підозрілий';
            } else {
                statusClass = 'status-danger'; // Ваш існуючий клас
                statusText = 'Фішинг';
            }

            item.innerHTML = `
                <span class="history-url">${scan.url}</span>
                <span class="history-status ${statusClass}">${statusText}</span>
                <button class="history-rescan-btn" data-url="${scan.url}" title="Пересканувати"><i class="fas fa-redo"></i></button>
            `;
            historyList.appendChild(item);
        });

        // Додати обробники для кнопки "Пересканувати"
        historyList.querySelectorAll('.history-rescan-btn').forEach(button => {
            button.addEventListener('click', (e) => {
                urlInput.value = e.currentTarget.dataset.url;
                urlForm.dispatchEvent(new Event('submit')); // Ініціювати сканування
            });
        });
    }

    // Ініціалізувати валідацію та історію при завантаженні сторінки
    validateUrl();
    renderScanHistory(); // Завантажуємо історію при старті
});