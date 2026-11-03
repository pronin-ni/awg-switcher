import { chromium } from 'playwright';
import { execFileSync, spawnSync } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { createServer } from 'node:net';
import { mkdir } from 'node:fs/promises';

const name = `awg-browser-${process.pid}`;
const volume = `${name}-data`;
const password = 'Browser-smoke-test-password-42';
const config = `[Interface]\nPrivateKey = <SYNTHETIC-TEST-NOT-SECRET>\nAddress = 172.16.0.2/32\n[Peer]\nPublicKey = synthetic-peer-key\nEndpoint = vpn.example.test:51820\nAllowedIPs = 0.0.0.0/0\n`;
let browser;

function docker(...args) {
  return execFileSync('docker', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

try {
  await mkdir('artifacts/automation-redesign', { recursive: true });
  docker('volume', 'create', volume);
  const portServer = createServer();
  await new Promise((resolve) => portServer.listen(0, '127.0.0.1', resolve));
  const hostPort = portServer.address().port;
  await new Promise((resolve, reject) => portServer.close((error) => error ? reject(error) : resolve()));
  docker('run', '-d', '--name', name, '--platform', 'linux/amd64', '--read-only',
    '--cap-drop=ALL', '--cap-add=CHOWN', '--cap-add=FOWNER', '--cap-add=SETGID', '--cap-add=SETUID',
    '--security-opt', 'no-new-privileges:true', '--tmpfs', '/run/awg-switcher:rw,noexec,nosuid,size=16m,uid=10001,gid=10001',
    '-p', `127.0.0.1:${hostPort}:8080`, '-v', `${volume}:/app/data`, 'awg-switcher:ci');
  const baseURL = `http://127.0.0.1:${hostPort}`;
  for (let attempt = 0; attempt < 40; attempt++) {
    try {
      const response = await fetch(`${baseURL}/api/setup/status`);
      if (response.ok) break;
    } catch {}
    if (attempt === 39) throw new Error('container Web UI did not become ready');
    await delay(250);
  }
  const logResult = spawnSync('docker', ['logs', name], { encoding: 'utf8' });
  const logs = `${logResult.stdout}${logResult.stderr}`;
  const token = logs.match(/setup_code=(\S+)/)?.[1];
  if (!token) throw new Error('missing one-time setup code in container logs');

  browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  page.on('pageerror', (error) => console.error('BROWSER PAGE ERROR:', error.stack || error));
  page.on('console', (message) => { if (message.type() === 'error') console.error('BROWSER CONSOLE:', message.text()); });
  await page.goto(baseURL);
  await page.locator('#setup-token').fill(token);
  await page.locator('#setup-password').fill(password);
  await page.locator('#setup-form button[type="submit"], #setup-form button').click();
  await page.locator('#login-form').waitFor({ state: 'visible' });
  await page.locator('#password').fill(password);
  await page.locator('#login-form button').click();
  await page.locator('#dashboard').waitFor({ state: 'visible' });
  await page.locator('#theme').click();
  if (!['dark', 'light'].includes(await page.locator('html').getAttribute('data-theme'))) throw new Error('theme toggle did not apply a light/dark theme');
  await page.locator('#language').click();
  if (!(await page.locator('.rail nav a[href="#website-monitor"]').textContent()).toLowerCase().includes('automation')) throw new Error('English navigation translation did not apply');
  await page.locator('#language').click();
  if (!(await page.locator('.rail nav a[href="#website-monitor"]').textContent()).includes('Автоматизация')) throw new Error('Russian navigation translation did not restore');
  await page.locator('#theme').click();
  await page.locator('.rail nav a[href="#dashboard"]').click();
  await page.locator('#dashboard').waitFor({ state: 'visible' });

  await page.locator('.rail nav a[href="#website-monitor"]').click();
  if (!(await page.locator('#automation-refresh-state').textContent()).includes('Загрузка состояния')) throw new Error('automation did not show its initial loading state');
  await page.waitForFunction(() => document.querySelector('#pool-ready-count')?.textContent !== '—');
  if (!(await page.locator('#pool-ready-count').textContent()).includes('Нет профилей')) throw new Error('an empty profile list must be distinct from zero working profiles');
  await page.locator('.rail nav a[href="#dashboard"]').click();
  await page.locator('#dashboard').waitFor({ state: 'visible' });

  await page.locator('.rail nav a[href="#profiles"]').click();
  await page.locator('#reserve-warning').waitFor({ state: 'visible' });
  await page.locator('#reserve-generate').waitFor({ state: 'visible' });
  await page.getByRole('button', { name: '＋ Сгенерировать WARP' }).waitFor();
  await page.locator('#generate-warp-open').click();
  await page.locator('#warp-generator-dialog').waitFor({ state: 'visible' });
  if ((await page.locator('#generator-url').inputValue()) !== 'https://awgconfig.com') {
    throw new Error('standard generator did not default to awgconfig.com');
  }
  await page.locator('#generator-mode').selectOption('awg31');
  await page.locator('#generator-count').selectOption('3');
  await page.locator('#generator-close').click();
  const input = page.locator('#modal-files');
  await input.setInputFiles([
    { name: 'primary.conf', mimeType: 'text/plain', buffer: Buffer.from(config) },
    { name: 'backup.conf', mimeType: 'text/plain', buffer: Buffer.from(config.replace('172.16.0.2', '172.16.0.3')) },
  ]);
  await page.locator('#profile-list .profile-row').nth(1).waitFor();
  const initialNames = await page.locator('#profile-list .profile-row .profile-name').allTextContents();
  if (initialNames[0] !== 'primary' || initialNames[1] !== 'backup') {
    throw new Error(`first profile was not primary: ${initialNames.join(' | ')}`);
  }
  const secondRow = page.locator('#profile-list .profile-row').nth(1);
  await secondRow.getByRole('button', { name: '↑' }).click();
  await page.waitForFunction(() => {
    const rows = [...document.querySelectorAll('#profile-list .profile-row')];
    return rows.length === 2 && rows[0].querySelector('.profile-name')?.textContent === 'backup';
  });
  const beforeRestart = await page.locator('#profile-list .profile-row').evaluateAll((rows) => rows.map((row) => row.querySelector('.profile-sub').textContent));
  if (!beforeRestart[0].includes('Приоритет 0') || !beforeRestart[1].includes('Приоритет 1')) {
    throw new Error(`unexpected priorities before restart: ${beforeRestart.join(' | ')}`);
  }
  page.on('dialog', (dialog) => dialog.accept());
  await page.locator('.rail nav a[href="#website-monitor"]').click();
  await page.locator('#website-monitor').waitFor({ state: 'visible' });
  await page.waitForFunction(() => document.querySelector('#pool-ready-count')?.textContent !== '—', null, { timeout: 10000 }).catch(async error => {
    console.error('Automation DOM at timeout:', await page.locator('#website-monitor').innerText());
    throw error;
  });
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.locator('#theme').click();
  await page.screenshot({ path: 'artifacts/automation-redesign/desktop-dark.png', fullPage: true });
  await page.locator('#theme').click();
  const automationHeading = await page.locator('#website-monitor h1').textContent();
  if (automationHeading !== 'Автоматизация') throw new Error(`unexpected automation heading: ${automationHeading}`);
  if (await page.locator('#website-monitor .automation-card').count() !== 2) throw new Error('automation overview must have exactly two compact cards');
  for (const viewport of [{ width: 1440, height: 900 }, { width: 1280, height: 800 }, { width: 390, height: 844 }]) {
    await page.setViewportSize(viewport);
    const layout = await page.locator('#website-monitor').evaluate(el => ({ width: el.clientWidth, scroll: el.scrollWidth }));
    if (layout.scroll > layout.width + 2) throw new Error(`automation UI overflows ${viewport.width}px viewport: ${JSON.stringify(layout)}`);
    if (viewport.width === 1280) await page.screenshot({ path: 'artifacts/automation-redesign/laptop.png', fullPage: true });
  }
  await page.setViewportSize({ width: 390, height: 844 });
  await page.locator('#mobile-menu-toggle').click();
  await page.locator('#primary-navigation').getByRole('link', { name: 'Автоматизация' }).waitFor({ state: 'visible' });
  if ((await page.locator('#mobile-menu-toggle').getAttribute('aria-expanded')) !== 'true') throw new Error('mobile navigation did not expose its expanded state');
  await page.screenshot({ path: 'artifacts/automation-redesign/mobile-menu.png', fullPage: true });
  await page.locator('#mobile-menu-toggle').click();
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.screenshot({ path: 'artifacts/automation-redesign/desktop.png', fullPage: true });
  if (!(await page.locator('#site-next-check').textContent()).includes('выключены')) throw new Error('disabled website checks do not show disabled schedule state');
  if (!(await page.locator('#site-last-run').textContent()).includes('Ещё не проверялся')) throw new Error('empty Website Monitor timestamp was rendered as a date');
  if (!(await page.locator('#pool-last-run').textContent()).includes('Ещё не запускалось')) throw new Error('empty replenishment timestamp was rendered as a date');
  const actualReadiness = await page.evaluate(() => {
    const { profiles, system } = window.awgAutomationState;
    return { total: profiles.length, ready: profiles.filter(p => p.healthy && (p.routing_eligible !== false || !system.website_monitor_enabled)).length };
  });
  const renderedReadyCount = (await page.locator('#pool-ready-count').textContent()).trim();
  const expectedReadiness = actualReadiness.total ? `${actualReadiness.ready} / ${actualReadiness.total}` : 'Нет профилей';
  if (renderedReadyCount !== expectedReadiness) throw new Error(`automation readiness differs from the backend/profile overview: UI=${renderedReadyCount}, backend=${expectedReadiness}`);
  const autoDefaults = await (await page.request.get(`${baseURL}/api/auto-replenishment/settings`)).json();
  if (autoDefaults.enabled !== false || autoDefaults.minimum_ready !== 2 || autoDefaults.target_ready !== 4) {
    throw new Error(`unexpected automatic replenishment defaults: ${JSON.stringify(autoDefaults)}`);
  }

  await page.locator('#site-settings-open').click();
  await page.locator('#site-settings-dialog').waitFor({ state: 'visible' });
  console.log('SMOKE: editing local website configuration');
  await page.screenshot({ path: 'artifacts/automation-redesign/site-settings.png', fullPage: true });
  await page.locator('#site-add-name').fill('GitHub API');
  await page.locator('#site-add-url').fill('https://api.github.com/');
  await page.locator('#site-add-button').click();
  await page.locator('#site-schedule-mode').selectOption('daily');
  await page.locator('#site-schedule-daily').fill('09:00');
  await page.locator('#site-settings-dialog .settings-advanced').evaluate(el => el.open = true);
  await page.locator('#site-schedule-timezone').fill('Europe/Moscow');
  await page.locator('#site-schedule-paused').check();
  await page.locator('#site-settings-form [type="submit"]').click();
  await page.locator('#site-settings-dialog').waitFor({ state: 'hidden' });
  await page.locator('#wm-enabled').check();
  await page.waitForFunction(async () => (await (await fetch('/api/website-monitor/settings')).json()).enabled === true);
  console.log('SMOKE: monitor enabled; validating setup state');
  await page.waitForFunction(() => document.querySelector('#site-state-pill')?.textContent === 'Требуется настройка');
  await page.screenshot({ path: 'artifacts/automation-redesign/website-setup-required.png', fullPage: true });
  await page.locator('#site-settings-open').click();
  await page.locator('#site-settings-dialog .settings-advanced').evaluate(el => el.open = true);
  await page.locator('#site-schedule-paused').uncheck();
  await page.locator('#site-settings-form [type="submit"]').click();
  await page.locator('#site-settings-dialog').waitFor({ state: 'hidden' });
  console.log('SMOKE: schedule unpaused; validating running state');
  await page.waitForFunction(() => document.querySelector('#site-state-pill')?.textContent === 'Работает');
  const websiteCheckResponse = page.waitForResponse(response => response.url().includes('/api/website-monitor/check'));
  await page.locator('#site-check-now').click();
  const realCheckResponse = await websiteCheckResponse;
  await page.waitForFunction(() => document.querySelector('#site-check-now')?.getAttribute('aria-busy') === 'false', null, { timeout: 90000 });
  const websiteStatus = await (await page.request.get(`${baseURL}/api/website-monitor/status`)).json();
  if (realCheckResponse.ok() && websiteStatus.last_check && (await page.locator('#site-last-run').textContent()).includes('Последняя проверка')) {
    console.log('PASS: website check result and passed-profile summary came from the local backend API');
  } else if (!realCheckResponse.ok() && !(await page.locator('#automation-toast').textContent()).trim()) {
    throw new Error(`backend check failed without user feedback: HTTP ${realCheckResponse.status()}`);
  }

  await page.locator('#pool-settings-open').click();
  await page.locator('#pool-settings-dialog').waitFor({ state: 'visible' });
  await page.screenshot({ path: 'artifacts/automation-redesign/pool-settings.png', fullPage: true });
  await page.locator('#pool-minimum-input').fill('3');
  await page.locator('#pool-target-input').fill('5');
  await page.locator('#pool-settings-dialog .settings-advanced:not(#pool-events-details)').evaluate(el => el.open = true);
  await page.locator('.pool-version[value="awg2"]').uncheck();
  await page.locator('#pool-below-minimum').uncheck();
  await page.locator('#pool-all-down').uncheck();
  await page.locator('#pool-settings-form [type="submit"]').click();
  await page.locator('#pool-settings-dialog').waitFor({ state: 'hidden' });
  await page.waitForFunction(async () => { const a=await (await fetch('/api/auto-replenishment/settings')).json(); return a.minimum_ready===3&&a.target_ready===5&&a.versions.length===2 });

  await page.locator('#auto-enabled').check();
  await page.waitForFunction(async () => (await (await fetch('/api/auto-replenishment/settings')).json()).enabled === true);
  await page.waitForFunction(async () => {
    const status = await (await fetch('/api/auto-replenishment/status')).json();
    return status.last_run_status !== '' && status.last_run_status !== 'running';
  }, null, { timeout: 20000 });
  await page.locator('#auto-enabled').uncheck();
  await page.waitForFunction(async () => (await (await fetch('/api/auto-replenishment/settings')).json()).enabled === false);

  let mockedPoolEnabled = false;
  await page.route('**/api/auto-replenishment/settings', async route => {
    if (route.request().method() === 'GET') {
      const response = await route.fetch();
      const data = await response.json();
      data.enabled = mockedPoolEnabled;
      return route.fulfill({ response, json: data });
    }
    const data = route.request().postDataJSON();
    mockedPoolEnabled = data.enabled;
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ saved: true, status: { running: mockedPoolEnabled } }) });
  });
  await page.route('**/api/auto-replenishment/status', async route => {
    const response = await route.fetch();
    const data = await response.json();
    data.running = mockedPoolEnabled;
    data.last_run_status = mockedPoolEnabled ? 'running' : '';
    return route.fulfill({ response, json: data });
  });
  await page.locator('#auto-enabled').check();
  await page.waitForFunction(() => document.querySelector('#pool-run-summary')?.textContent.includes('Проверяем новые профили'));
  if (!(await page.locator('#pool-state-pill').textContent()).includes('Проверка')) throw new Error('active replenishment was not shown as running');
  await page.waitForFunction(() => !document.querySelector('#automation-toast')?.classList.contains('is-visible'));
  await page.screenshot({ path: 'artifacts/automation-redesign/generation-active.png', fullPage: true });
  await page.locator('#auto-enabled').uncheck();
  await page.waitForFunction(() => document.querySelector('#pool-state-pill')?.textContent === 'Выключено');
  await page.unroute('**/api/auto-replenishment/settings');
  await page.unroute('**/api/auto-replenishment/status');

  await page.route('**/api/profiles', route => route.fulfill({ status: 503, body: 'synthetic test outage' }));
  await page.locator('.rail nav a[href="#dashboard"]').click();
  await page.locator('.rail nav a[href="#website-monitor"]').click();
  await page.locator('#automation-error').waitFor({ state: 'visible' });
  await page.unroute('**/api/profiles');
  await page.locator('#automation-retry').click();
  await page.locator('#automation-error').waitFor({ state: 'hidden' });

  await page.setViewportSize({ width: 390, height: 844 });
  await page.waitForFunction(() => !document.querySelector('#automation-toast')?.classList.contains('is-visible'));
  await delay(250);
  await page.screenshot({ path: 'artifacts/automation-redesign/mobile.png', fullPage: true });
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.locator('#logout').click();
  docker('restart', name);
  for (let attempt = 0; attempt < 40; attempt++) {
    try {
      if ((await fetch(`${baseURL}/api/setup/status`)).ok) break;
    } catch {}
    if (attempt === 39) throw new Error(`container did not recover after restart; state=${docker('inspect', '-f', '{{.State.Status}} {{.State.ExitCode}}', name)} logs=${spawnSync('docker', ['logs', name], { encoding: 'utf8' }).stderr}`);
    await delay(250);
  }
  await page.reload();
  await page.locator('#password').fill(password);
  await page.locator('#login-form button').click();
  await page.locator('#dashboard').waitFor({ state: 'visible' });
  await page.locator('.rail nav a[href="#profiles"]').click();
  await page.locator('#profile-list .profile-row').nth(1).waitFor();
  const restoredNames = await page.locator('#profile-list .profile-row .profile-name').allTextContents();
  if (restoredNames[0] !== 'backup' || restoredNames[1] !== 'primary') {
    throw new Error(`profile order changed on restart: ${restoredNames.join(' | ')}`);
  }
  const afterRestart = await page.locator('#profile-list .profile-row').evaluateAll((rows) => rows.map((row) => row.querySelector('.profile-sub').textContent));
  if (!afterRestart[0].includes('Приоритет 0') || !afterRestart[1].includes('Приоритет 1')) {
    throw new Error(`priorities changed after restart: ${afterRestart.join(' | ')}`);
  }
  await page.locator('.rail nav a[href="#website-monitor"]').click();
  await page.waitForFunction(async () => { const s=await (await fetch('/api/website-monitor/settings')).json(); return s.enabled===true&&s.schedule.mode==='daily'&&s.schedule.timezone==='Europe/Moscow'&&s.schedule.paused===false&&s.websites.some(w=>w.name==='GitHub API') });
  await page.waitForFunction(async () => { const s=await (await fetch('/api/auto-replenishment/settings')).json(); return s.enabled===false&&s.minimum_ready===3&&s.target_ready===5&&s.versions.length===2 });
  await page.locator('a[href="#diagnostics"]').click();
  await page.locator('#network-debug').check();
  await page.locator('#debug-state').getByText('активна').waitFor();
  await page.locator('#network-debug').uncheck();
  await page.locator('#debug-state').getByText('выключена').waitFor();
  const downloadPromise = page.waitForEvent('download');
  await page.locator('#download-support').click();
  const report = await downloadPromise;
  if (report.suggestedFilename() !== 'awg-switcher-support.json') throw new Error('unexpected support report filename');
  console.log('PASS: first-run setup, login, WARP generator, profile and automation restart persistence, two-card automation UI at desktop/laptop/mobile, settings dialogs and Network Debug');
} finally {
  await browser?.close();
  try { docker('rm', '-f', name); } catch {}
  try { docker('volume', 'rm', volume); } catch {}
}
