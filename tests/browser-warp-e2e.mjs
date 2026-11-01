// Manual live E2E: performs one real registration with awgconfig.com and tests
// the returned profile through the real Linux wireproxy engine. Never print
// generated configuration, keys, cookies, or raw engine/API logs.
import { chromium } from 'playwright';
import { execFileSync, spawnSync } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { createServer } from 'node:net';

const name = `awg-warp-e2e-${process.pid}`;
const volume = `${name}-data`;
const password = 'Live-browser-test-password-42';
let browser;

function docker(...args) {
  return execFileSync('docker', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

try {
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
  for (let attempt = 0; attempt < 60; attempt++) {
    try {
      if ((await fetch(`${baseURL}/api/setup/status`)).ok) break;
    } catch {}
    if (attempt === 59) throw new Error('application did not become ready');
    await delay(500);
  }
  const logResult = spawnSync('docker', ['logs', name], { encoding: 'utf8' });
  const logs = `${logResult.stdout}${logResult.stderr}`;
  const token = logs.match(/setup_code=(\S+)/)?.[1];
  if (!token) throw new Error('initial setup code unavailable');

  browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  await page.goto(baseURL);
  await page.locator('#setup-token').fill(token);
  await page.locator('#setup-password').fill(password);
  await page.locator('#setup-form button').click();
  await page.locator('#login-form').waitFor({ state: 'visible' });
  await page.locator('#password').fill(password);
  await page.locator('#login-form button').click();
  await page.locator('#dashboard').waitFor({ state: 'visible' });
  await page.locator('.rail nav a[href="#profiles"]').click();
  await page.locator('#generate-warp-open').click();
  await page.locator('#generator-mode').selectOption('awg2');
  await page.locator('#generator-count').selectOption('1');
  await page.locator('#generate-warp').click();
  await page.locator('.generator-outcome').waitFor({ timeout: 240000 });
  const resultText = await page.locator('.generator-outcome').first().innerText();
  if (!resultText.includes('HTTPS-проверка пройдена')) {
    throw new Error(`live generated profile did not pass engine HTTPS verification: ${resultText}`);
  }
  const profileName = (await page.locator('.generator-outcome strong').first().textContent()).trim();
  await page.locator('#generator-close').click();
  await page.locator('.rail nav a[href="#profiles"]').click();
  await page.locator('#profile-list .profile-row').filter({ hasText: profileName }).waitFor({ timeout: 15000 });
  const row = page.locator('#profile-list .profile-row').filter({ hasText: profileName });
  if (await row.innerText().then((text) => text.includes('ОТКЛЮЧЕН'))) {
    throw new Error('HTTPS-verified profile was unexpectedly left disabled');
  }
  const appLogs = spawnSync('docker', ['logs', name], { encoding: 'utf8' });
  if (/(?:PrivateKey|PresharedKey)\s*=\s*[A-Za-z0-9+/=]{20,}/i.test(`${appLogs.stdout}${appLogs.stderr}`)) {
    throw new Error('private key material was detected in container logs');
  }
  console.log('PASS: browser → awgconfig.com → validated import → real wireproxy engine + HTTPS check → enabled backup visible in Profiles. Generated secrets were not logged.');
} finally {
  await browser?.close();
  try { docker('rm', '-f', name); } catch {}
  try { docker('volume', 'rm', volume); } catch {}
}
