(() => {
  'use strict';

  const $ = (selector) => document.querySelector(selector);
  let csrf = '';
  let eligibleIDs = [];

  async function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    if (options.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
    if (options.method && options.method !== 'GET') {
      if (!csrf) {
        const session = await fetch('/api/session');
        if (!session.ok) throw new Error('Административная сессия истекла. Войдите повторно.');
        csrf = (await session.json()).csrf;
      }
      headers.set('X-CSRF-Token', csrf);
    }
    const response = await fetch(path, { ...options, headers });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const retry = response.headers.get('Retry-After');
      const message = data.message || data.error || `HTTP ${response.status}`;
      throw new Error(retry ? `${message} (повторите через ${retry} с)` : message);
    }
    return data;
  }

  async function loadSettings() {
    try {
      const settings = await api('/api/config-generator/settings');
      $('#generator-url').value = settings.url;
      $('#generator-settings-status').textContent = settings.token_configured
        ? 'Сохранён Bearer-токен. Endpoint mode: hostname; Lab Auto отключён.'
        : 'Токен не сохранён. Endpoint mode: hostname; Lab Auto отключён.';
    } catch (error) {
      $('#generator-settings-status').textContent = error.message;
    }
  }

  $('#generator-save').addEventListener('click', async () => {
    const status = $('#generator-settings-status');
    status.textContent = 'Сохранение настроек…';
    const body = { url: $('#generator-url').value, clear_token: $('#generator-clear-token').checked };
    if ($('#generator-token').value) body.bearer_token = $('#generator-token').value;
    try {
      const result = await api('/api/config-generator/settings', { method: 'POST', body: JSON.stringify(body) });
      $('#generator-token').value = '';
      $('#generator-clear-token').checked = false;
      status.textContent = result.token_configured
        ? 'Настройки сохранены; Bearer-токен защищённо сохранён на сервере.'
        : 'Настройки сохранены. Endpoint mode: hostname; Lab Auto отключён.';
    } catch (error) {
      status.textContent = `Не удалось сохранить настройки: ${error.message}`;
    }
  });

  $('#generator-test').addEventListener('click', async () => {
    const status = $('#generator-settings-status');
    status.textContent = 'Проверка /api/status…';
    try {
      const result = await api('/api/config-generator/test', { method: 'POST', body: '{}' });
      status.textContent = result.message;
    } catch (error) {
      status.textContent = `Генератор недоступен: ${error.message}`;
    }
  });

  $('#generate-warp').addEventListener('click', async () => {
    const resultNode = $('#generator-result');
    const actions = $('#generator-enable-actions');
    actions.replaceChildren();
    eligibleIDs = [];
    resultNode.textContent = 'Запрос генерации и отдельная HTTPS-проверка каждого профиля могут занять до нескольких минут…';
    try {
      const result = await api('/api/config-generator/generate', {
        method: 'POST',
        body: JSON.stringify({ mode: $('#generator-mode').value, count: Number($('#generator-count').value) }),
      });
      eligibleIDs = result.eligible_profile_ids || [];
      resultNode.textContent = JSON.stringify(result, null, 2);
      if (eligibleIDs.length) {
        const button = document.createElement('button');
        button.className = 'primary';
        button.textContent = `Включить ${eligibleIDs.length} HTTPS-проверенных профилей в автоматический failover`;
        button.addEventListener('click', async () => {
          button.disabled = true;
          try {
            for (const id of eligibleIDs) {
              await api(`/api/profiles/${encodeURIComponent(id)}`, {
                method: 'PATCH', body: JSON.stringify({ enabled: true }),
              });
            }
            button.textContent = 'Профили включены; основной профиль автоматически не менялся';
            window.dispatchEvent(new Event('awg-profiles-updated'));
          } catch (error) {
            button.disabled = false;
            button.textContent = `Не все профили включены: ${error.message}`;
          }
        });
        actions.append(button);
      }
      window.dispatchEvent(new Event('awg-profiles-updated'));
    } catch (error) {
      resultNode.textContent = `Генерация не выполнена: ${error.message}`;
    }
  });

  window.addEventListener('awg-profiles-updated', () => {
    // The existing dashboard refreshes profile state every five seconds.
  });
  loadSettings();
})();
