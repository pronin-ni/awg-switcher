(() => {
  'use strict';

  const $ = (selector) => document.querySelector(selector);
  let csrf = '';
  let settingsLoaded = false;

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
    const response = await fetch(path, { ...options, headers, cache: 'no-store' });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const retry = response.headers.get('Retry-After');
      const message = data.message || data.error || `HTTP ${response.status}`;
      throw new Error(retry ? `${message} (повторите через ${retry} с)` : message);
    }
    return data;
  }

  function showOutcome(result) {
    const root = $('#generator-result');
    root.replaceChildren();
    const lang = localStorage.getItem('awg-lang') || 'ru';
    const t = (ru, en) => lang === 'ru' ? ru : en;
    const profiles = result.profiles || [];
    const created = Number.isFinite(Number(result.generated)) ? Number(result.generated) : profiles.length;
    const verified = profiles.filter((profile) => profile.verified).length;
    const reserve = profiles.filter((profile) => profile.enabled && profile.routing_eligible !== false).length;
    const failed = profiles.length - verified;
    const summary = document.createElement('p');
    summary.className = 'generator-counts';
    summary.textContent = `${t('Создано конфигов','Configs created')}: ${created} · ${t('Проверено успешно','Verified')}: ${verified} · ${t('Добавлено в резерв','Added as backup')}: ${reserve} · ${t('Не прошло проверку','Failed')}: ${failed}`;
    root.append(summary);
    const nextStep = document.createElement('p');
    nextStep.className = 'small muted';
    nextStep.textContent = failed
      ? t('Профили с ошибкой сохранены выключенными. Откройте профиль и проверьте причину; VPN-маршрут не изменён.','Failed profiles remain disabled. Review their reason; the active VPN route was not changed.')
      : t('Дополнительные действия не требуются. Новые профили добавлены в резерв; текущий маршрут не изменён.','No further action is needed. New profiles were added as backups; the active route was not changed.');
    root.append(nextStep);
    for (const profile of profiles) {
      const row = document.createElement('div');
      row.className = `generator-outcome ${profile.verified ? 'is-ok' : 'is-error'}`;
      const title = document.createElement('strong');
      title.textContent = profile.profile_name || `Профиль ${profile.index}`;
      const detail = document.createElement('span');
      if (profile.verified) {
        detail.textContent = t('HTTPS-проверка пройдена · добавлен в резерв','HTTPS check passed · added as backup');
      } else if (profile.saved) {
        detail.textContent = `${t('Сохранён, но оставлен выключенным','Saved but left disabled')}: ${profile.failure_reason || t('проверка не пройдена','verification failed')}`;
      } else {
        detail.textContent = `${t('Не импортирован','Not imported')}: ${profile.failure_reason || t('неизвестная ошибка','unknown error')}`;
      }
      row.append(title, detail);
      root.append(row);
    }
    if (result.generator_warning) {
      const warning = document.createElement('p');
      warning.className = 'small muted';
      warning.textContent = `${t('Предупреждение генератора','Generator warning')}: ${result.generator_warning}`;
      root.append(warning);
    }
  }

  $('#generate-warp-open').addEventListener('click', () => {
    $('#generator-result').replaceChildren();
    $('#warp-generator-dialog').showModal();
    if (!settingsLoaded) loadSettings();
  });
  $('#reserve-generate').addEventListener('click', () => $('#generate-warp-open').click());
  $('#generator-close').addEventListener('click', () => $('#warp-generator-dialog').close());

  $('#generator-save').addEventListener('click', async () => {
    const status = $('#generator-settings-status');
    status.textContent = 'Сохранение настроек…';
    const body = { url: $('#generator-url').value, clear_token: $('#generator-clear-token').checked };
    if ($('#generator-token').value) body.bearer_token = $('#generator-token').value;
    try {
      const result = await api('/api/config-generator/settings', { method: 'POST', body: JSON.stringify(body) });
      $('#generator-token').value = '';
      $('#generator-clear-token').checked = false;
      settingsLoaded = true;
      status.textContent = result.token_configured
        ? 'Настройки сохранены; Bearer-токен защищённо хранится на сервере.'
        : 'Настройки сохранены.';
    } catch (error) {
      status.textContent = `Не удалось сохранить настройки: ${error.message}`;
    }
  });

  $('#generator-test').addEventListener('click', async () => {
    const status = $('#generator-settings-status');
    status.textContent = 'Проверка соединения…';
    try {
      const result = await api('/api/config-generator/test', { method: 'POST', body: '{}' });
      status.textContent = result.message;
    } catch (error) {
      status.textContent = `Генератор недоступен: ${error.message}`;
    }
  });

  $('#generate-warp').addEventListener('click', async (event) => {
    const button = event.currentTarget;
    const resultNode = $('#generator-result');
    button.disabled = true;
    resultNode.textContent = 'Запрос к awgconfig.com, импорт и HTTPS-проверка каждого профиля. Это может занять до нескольких минут…';
    try {
      const result = await api('/api/config-generator/generate', {
        method: 'POST',
        body: JSON.stringify({ mode: $('#generator-mode').value, count: Number($('#generator-count').value) }),
      });
      showOutcome(result);
      window.dispatchEvent(new Event('awg-profiles-updated'));
    } catch (error) {
      resultNode.textContent = `Не удалось сгенерировать профили: ${error.message}`;
    } finally {
      button.disabled = false;
    }
  });

  async function loadSettings() {
    try {
      const settings = await api('/api/config-generator/settings');
      $('#generator-url').value = settings.url;
      settingsLoaded = true;
      $('#generator-settings-status').textContent = settings.token_configured
        ? 'Self-hosted Bearer-токен настроен.'
        : 'Используется стандартный API awgconfig.com.';
    } catch (error) {
      $('#generator-settings-status').textContent = error.message;
    }
  }
})();
