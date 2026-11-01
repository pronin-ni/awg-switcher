import { chromium } from 'playwright';
import { execFileSync, spawnSync } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { createServer } from 'node:net';

const name = `awg-browser-${process.pid}`;
const volume = `${name}-data`;
const password = 'Browser-smoke-test-password-42';
const config = `[Interface]\nPrivateKey = <SYNTHETIC-TEST-NOT-SECRET>\nAddress = 172.16.0.2/32\n[Peer]\nPublicKey = synthetic-peer-key\nEndpoint = vpn.example.test:51820\nAllowedIPs = 0.0.0.0/0\n`;
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
  await page.goto(baseURL);
  await page.locator('#setup-token').fill(token);
  await page.locator('#setup-password').fill(password);
  await page.locator('#setup-form button[type="submit"], #setup-form button').click();
  await page.locator('#login-form').waitFor({ state: 'visible' });
  await page.locator('#password').fill(password);
  await page.locator('#login-form button').click();
  await page.locator('#dashboard').waitFor({ state: 'visible' });
  await page.locator('a[href="#dashboard"]').click();
  await page.locator('#dashboard').waitFor({ state: 'visible' });

  await page.locator('a[href="#profiles"]').click();
  const input = page.locator('#files');
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
  const beforeRestart = await page.locator('#profile-list .profile-row .profile-sub').allTextContents();
  if (!beforeRestart[0].includes('Приоритет 0') || !beforeRestart[1].includes('Приоритет 1')) {
    throw new Error(`unexpected priorities before restart: ${beforeRestart.join(' | ')}`);
  }
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
  await page.locator('a[href="#profiles"]').click();
  await page.locator('#profile-list .profile-row').nth(1).waitFor();
  const restoredNames = await page.locator('#profile-list .profile-row .profile-name').allTextContents();
  if (restoredNames[0] !== 'backup' || restoredNames[1] !== 'primary') {
    throw new Error(`profile order changed on restart: ${restoredNames.join(' | ')}`);
  }
  const afterRestart = await page.locator('#profile-list .profile-row .profile-sub').allTextContents();
  if (!afterRestart[0].includes('Приоритет 0') || !afterRestart[1].includes('Приоритет 1')) {
    throw new Error(`priorities changed after restart: ${afterRestart.join(' | ')}`);
  }
  await page.locator('a[href="#diagnostics"]').click();
  await page.locator('#network-debug').check();
  await page.locator('#debug-state').getByText('активна').waitFor();
  await page.locator('#network-debug').uncheck();
  await page.locator('#debug-state').getByText('выключена').waitFor();
  const downloadPromise = page.waitForEvent('download');
  await page.locator('#download-support').click();
  const report = await downloadPromise;
  if (report.suggestedFilename() !== 'awg-switcher-support.json') throw new Error('unexpected support report filename');
  console.log('PASS: first-run setup, login, profile upload/order persistence, Network Debug toggle and support report download');
} finally {
  await browser?.close();
  try { docker('rm', '-f', name); } catch {}
  try { docker('volume', 'rm', volume); } catch {}
}
